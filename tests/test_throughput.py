import asyncio
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import UploadFile

import app as service


def source_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('project/main.py', 'print("hello")\n')
    return buffer.getvalue()


def days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')


class ServiceTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, value in {
            'DATA_DIR': self.root,
            'DB_PATH': self.root / 'scans.sqlite3',
            'JOB_QUEUE': asyncio.Queue(maxsize=10),
            'RECOVERING': False,
            'RETENTION_DAYS': 30,
        }.items():
            patcher = patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        service.initialize_storage()
        inventory = patch.object(service, 'scanner_inventory', return_value=[
            {'name': name, 'available': True} for name in service.SCANNER_BINARIES
        ])
        inventory.start()
        self.addCleanup(inventory.stop)

    def seed(self, status='queued', scanners=None, created_at=None, upload=True):
        scan_id = uuid.uuid4().hex
        directory = service.job_dir(scan_id)
        directory.mkdir(parents=True)
        payload = source_zip()
        if upload:
            (directory / 'source.zip').write_bytes(payload)
        created = created_at or service.utc_now()
        with service.connect_db() as db:
            db.execute(
                'INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (scan_id, 'test', status, created, created, json.dumps(scanners or ['semgrep']), len(payload)),
            )
        return scan_id


class StorageTests(ServiceTestCase):
    def test_utc_now_is_fixed_width_so_text_order_is_time_order(self):
        self.assertRegex(service.utc_now(), r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$')
        self.assertLess(days_ago(31), days_ago(30))

    def test_prune_removes_only_expired_terminal_scans(self):
        expired = [self.seed(status, created_at=days_ago(31)) for status in ('completed', 'partial', 'failed')]
        kept = [
            self.seed('queued', created_at=days_ago(31)),
            self.seed('running', created_at=days_ago(31)),
            self.seed('completed', created_at=days_ago(29)),
        ]
        self.assertEqual(service.prune_expired(), 3)
        for scan_id in expired:
            self.assertIsNone(service.get_scan_row(scan_id))
            self.assertFalse(service.job_dir(scan_id).exists())
        for scan_id in kept:
            self.assertIsNotNone(service.get_scan_row(scan_id))
            self.assertTrue(service.job_dir(scan_id).exists())

    def test_prune_deletes_files_without_holding_a_write_lock(self):
        for _ in range(2):
            self.seed('completed', created_at=days_ago(40))
        other = self.seed('queued')
        original_rmtree = service.shutil.rmtree
        deleted = []

        def rmtree(path, *args, **kwargs):
            # With timeout=0 this write fails at once if prune holds the write lock.
            db = sqlite3.connect(service.DB_PATH, timeout=0)
            try:
                with db:
                    db.execute('UPDATE scans SET updated_at = ? WHERE id = ?', (service.utc_now(), other))
            finally:
                db.close()
            deleted.append(path)
            return original_rmtree(path, *args, **kwargs)

        with patch.object(service.shutil, 'rmtree', side_effect=rmtree):
            self.assertEqual(service.prune_expired(), 2)
        self.assertEqual(len(deleted), 2)

    async def test_upload_does_not_prune(self):
        upload = UploadFile(file=io.BytesIO(source_zip()), filename='source.zip')
        with patch.object(service, 'prune_expired', side_effect=AssertionError('upload pruned')):
            response = await service.create_scan(upload, 'semgrep', 'test')
        self.assertEqual(response['status'], 'queued')

    async def test_pruning_runs_at_startup_and_periodically(self):
        loop = asyncio.get_running_loop()
        pruned = asyncio.Event()
        calls = 0

        def prune():
            nonlocal calls
            calls += 1
            if calls >= 3:
                loop.call_soon_threadsafe(pruned.set)
            return 0

        with patch.object(service, 'prune_expired', side_effect=prune), \
             patch.object(service, 'PRUNE_INTERVAL_SECONDS', 0.01):
            async with service.lifespan(service.app):
                await asyncio.wait_for(pruned.wait(), timeout=5)
        self.assertGreaterEqual(calls, 3)

    async def test_list_and_get_use_stored_summary_without_reading_report(self):
        scan_id = self.seed(scanners=['semgrep', 'trivy'])
        results = [({'name': 'semgrep', 'status': 'completed'}, []), ({'name': 'trivy', 'status': 'failed'}, [])]
        with patch.object(service, 'run_scanner', new=AsyncMock(side_effect=results)):
            await service.process_scan(scan_id)
        expected = service.get_scan(scan_id)
        self.assertEqual(expected['summary']['scanners_completed'], 1)
        self.assertEqual([scanner['name'] for scanner in expected['scanner_results']], ['semgrep', 'trivy'])
        self.assertTrue((service.job_dir(scan_id) / 'report.json').is_file())
        with patch.object(service.Path, 'read_text', side_effect=AssertionError('report.json was read')):
            self.assertEqual(service.get_scan(scan_id), expected)
            self.assertEqual(service.list_scans()['scans'], [expected])

    def test_legacy_rows_read_report_once_and_backfill(self):
        scan_id = self.seed('completed', upload=False)
        report = {
            'summary': {'total_findings': 2},
            'scanners': [{'name': 'semgrep', 'status': 'completed'}],
            'findings': [],
        }
        (service.job_dir(scan_id) / 'report.json').write_text(json.dumps(report), 'utf-8')
        first = service.get_scan(scan_id)
        self.assertEqual(first['summary'], report['summary'])
        self.assertEqual(first['scanner_results'], report['scanners'])
        self.assertEqual(json.loads(service.get_scan_row(scan_id)['summary_json']), report['summary'])
        with patch.object(service.Path, 'read_text', side_effect=AssertionError('report.json was read again')):
            self.assertEqual(service.get_scan(scan_id), first)

    def test_scans_without_report_keep_response_shape(self):
        scan = service.get_scan(self.seed('queued'))
        self.assertNotIn('summary', scan)
        self.assertNotIn('scanner_results', scan)

    def test_migration_upgrades_existing_database_in_place(self):
        legacy = self.root / 'legacy.sqlite3'
        db = sqlite3.connect(legacy)
        try:
            with db:
                db.execute(
                    'CREATE TABLE scans (id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, '
                    'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, finished_at TEXT, '
                    'scanners_json TEXT NOT NULL, upload_bytes INTEGER NOT NULL, error TEXT)'
                )
                db.execute(
                    "INSERT INTO scans VALUES ('a', 'old', 'completed', '2026-01-01T00:00:00+00:00', "
                    "'2026-01-01T00:00:00+00:00', NULL, '[\"semgrep\"]', 1, NULL)"
                )
        finally:
            db.close()
        with patch.object(service, 'DB_PATH', legacy):
            service.initialize_storage()
            service.initialize_storage()
            columns = [column['name'] for column in service.connect_db().execute('PRAGMA table_info(scans)')]
            indexes = {index['name'] for index in service.connect_db().execute('PRAGMA index_list(scans)')}
            row = service.get_scan_row('a')
        self.assertEqual(columns[-2:], ['summary_json', 'scanner_results_json'])
        self.assertLessEqual({'scans_status_created_at', 'scans_created_at'}, indexes)
        self.assertEqual((row['name'], row['status'], row['summary_json']), ('old', 'completed', None))

    def test_update_scan_rejects_unknown_fields(self):
        scan_id = self.seed('queued')
        with self.assertRaisesRegex(ValueError, 'not_a_column'):
            service.update_scan(scan_id, status='completed', not_a_column='x')
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'queued')


class FakeScanners:
    """Stand-in for run_scanner that records how many scanners overlap."""

    def __init__(self, delays=None, findings=None, gate=None):
        self.delays = delays or {}
        self.findings = findings or {}
        self.gate = gate
        self.running = []
        self.started = []
        self.max_total = 0
        self.max_by_name = {}

    async def run(self, name, source_root, work_dir):
        self.running.append(name)
        self.started.append(name)
        self.max_total = max(self.max_total, len(self.running))
        self.max_by_name[name] = max(self.max_by_name.get(name, 0), self.running.count(name))
        try:
            if self.gate is not None:
                await self.gate.wait()
            else:
                await asyncio.sleep(self.delays.get(name, 0.02))
        finally:
            self.running.remove(name)
        result = {'name': name, 'status': 'completed', 'duration_seconds': self.delays.get(name, 0.02)}
        return result, list(self.findings.get(name, []))


class ConcurrencyTests(ServiceTestCase):
    def settings(self, *, scans=1, parallel=1, total=None, limits=None):
        return patch.multiple(
            service,
            SCAN_CONCURRENCY=scans,
            SCANNER_PARALLELISM=parallel,
            MAX_SCANNER_PROCESSES=total or scans * parallel,
            SCANNER_PROCESS_LIMITS=dict(service.DEFAULT_SCANNER_PROCESS_LIMITS) if limits is None else limits,
            SCANNER_SLOTS=None,
        )

    async def wait_until(self, condition, timeout=5):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not condition():
            if loop.time() > deadline:
                self.fail('condition was not reached in time')
            await asyncio.sleep(0.005)

    @staticmethod
    def read_pid(path):
        try:
            text = path.read_text().strip()
        except OSError:
            return None
        return int(text) if text.isdigit() else None

    async def test_default_settings_run_scanners_one_at_a_time_in_order(self):
        names = ['osv-scanner', 'semgrep', 'gitleaks', 'trivy']
        scan_id = self.seed(scanners=names)
        fake = FakeScanners()
        with self.settings(), patch.object(service, 'run_scanner', new=fake.run):
            await service.process_scan(scan_id)
        self.assertEqual(fake.started, names)
        self.assertEqual(fake.max_total, 1)
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'completed')

    async def test_scan_concurrency_runs_queued_scans_at_the_same_time(self):
        ids = [self.seed(scanners=['gitleaks']) for _ in range(2)]
        both_running = asyncio.Event()
        active = set()

        async def scanner(name, source_root, work_dir):
            active.add(work_dir)
            if len(active) == 2:
                both_running.set()
            await asyncio.wait_for(both_running.wait(), timeout=5)
            return {'name': name, 'status': 'completed'}, []

        with self.settings(scans=2), patch.object(service, 'run_scanner', side_effect=scanner):
            async with service.lifespan(service.app):
                await asyncio.wait_for(both_running.wait(), timeout=5)
                await asyncio.wait_for(service.JOB_QUEUE.join(), timeout=5)
        self.assertEqual([service.get_scan_row(scan_id)['status'] for scan_id in ids], ['completed', 'completed'])

    async def test_parallel_report_matches_sequential_report(self):
        names = ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']
        # Later scanners finish first, and every scanner reports the same 'shared' finding.
        delays = {'semgrep': 0.08, 'gitleaks': 0.06, 'trivy': 0.04, 'osv-scanner': 0.02}
        findings = {
            name: [
                {'id': f'{name}-1', 'tool': name, 'severity': 'high', 'title': 'one'},
                {'id': 'shared', 'tool': name, 'severity': 'low', 'title': 'shared'},
                {'id': f'{name}-2', 'tool': name, 'severity': 'medium', 'title': 'two'},
            ]
            for name in names
        }
        reports = {}
        for parallel in (1, 4):
            scan_id = self.seed(scanners=names)
            fake = FakeScanners(delays, findings)
            with self.settings(parallel=parallel), patch.object(service, 'MAX_FINDINGS', 5), \
                 patch.object(service, 'run_scanner', new=fake.run):
                await service.process_scan(scan_id)
            self.assertEqual(fake.max_total, parallel)
            report = service.get_report(scan_id)
            reports[parallel] = {key: report[key] for key in ('summary', 'scanners', 'findings')}
        self.assertEqual(reports[4], reports[1])
        self.assertEqual([finding['id'] for finding in reports[4]['findings']],
                         ['semgrep-1', 'shared', 'semgrep-2', 'gitleaks-1', 'gitleaks-2'])
        self.assertEqual(reports[4]['findings'][1]['tool'], 'semgrep')
        self.assertTrue(reports[4]['summary']['findings_truncated'])
        self.assertEqual([scanner['name'] for scanner in reports[4]['scanners']], names)

    async def test_trivy_never_runs_twice_across_concurrent_scans(self):
        ids = [self.seed(scanners=['trivy', 'gitleaks']) for _ in range(2)]
        gate = asyncio.Event()
        fake = FakeScanners(gate=gate)
        with self.settings(scans=2, parallel=2), patch.object(service, 'run_scanner', new=fake.run):
            scans = asyncio.gather(*(service.process_scan(scan_id) for scan_id in ids))
            try:
                await self.wait_until(lambda: len(fake.running) == 3)
                await asyncio.sleep(0.05)  # room for a wrongly unlimited second Trivy to start
                self.assertEqual(sorted(fake.running), ['gitleaks', 'gitleaks', 'trivy'])
            finally:
                gate.set()
                await scans
        self.assertEqual(fake.max_by_name['trivy'], 1)
        self.assertEqual(fake.started.count('trivy'), 2)

    async def test_total_process_cap_holds_across_scans(self):
        names = ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']
        ids = [self.seed(scanners=names) for _ in range(2)]
        gate = asyncio.Event()
        fake = FakeScanners(gate=gate)
        with self.settings(scans=2, parallel=4, total=3, limits={}), \
             patch.object(service, 'run_scanner', new=fake.run):
            scans = asyncio.gather(*(service.process_scan(scan_id) for scan_id in ids))
            try:
                await self.wait_until(lambda: len(fake.running) == 3)
                await asyncio.sleep(0.05)
                self.assertEqual(len(fake.running), 3)
            finally:
                gate.set()
                await scans
        self.assertEqual(fake.max_total, 3)
        self.assertEqual(len(fake.started), 8)

    async def test_cancelling_a_parallel_scan_stops_every_scanner_process(self):
        names = ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']
        scan_id = self.seed(scanners=names)
        work_dir = service.job_dir(scan_id) / 'work'
        script = 'import os, sys, time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(60)'

        def command(name, source_root, raw_output):
            return [sys.executable, '-c', script, str(work_dir / f'{name}.pid')]

        with self.settings(parallel=4, limits={}), patch.object(service, 'scanner_command', side_effect=command):
            task = asyncio.create_task(service.process_scan(scan_id))
            await self.wait_until(lambda: all(self.read_pid(work_dir / f'{name}.pid') for name in names), timeout=20)
            pids = [self.read_pid(work_dir / f'{name}.pid') for name in names]
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        self.assertEqual([task for task in asyncio.all_tasks() if task.get_name().startswith('whitebox-scanner-')], [])
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'queued')
        self.assertTrue((service.job_dir(scan_id) / 'source.zip').is_file())

    async def test_restart_requeues_every_interrupted_scan(self):
        ids = [self.seed(scanners=['gitleaks']) for _ in range(12)]
        running = set()
        both_running = asyncio.Event()

        async def blocked(name, source_root, work_dir):
            running.add(work_dir)
            if len(running) == 2:
                both_running.set()
            await asyncio.Event().wait()

        with self.settings(scans=2), patch.object(service, 'run_scanner', side_effect=blocked):
            async with service.lifespan(service.app):
                await asyncio.wait_for(both_running.wait(), timeout=5)
        rows = [service.get_scan_row(scan_id) for scan_id in ids]
        self.assertEqual({row['status'] for row in rows}, {'queued'})
        self.assertEqual(sum(row['error'] is not None for row in rows), 2)
        self.assertTrue(all((service.job_dir(scan_id) / 'source.zip').is_file() for scan_id in ids))

        finished = AsyncMock(return_value=({'name': 'gitleaks', 'status': 'completed'}, []))
        with self.settings(scans=2), patch.object(service, 'run_scanner', new=finished):
            async with service.lifespan(service.app):
                await self.wait_until(
                    lambda: all(service.get_scan_row(scan_id)['status'] == 'completed' for scan_id in ids),
                    timeout=10,
                )
        self.assertEqual(finished.await_count, 12)

    async def test_joern_works_outside_the_source_tree(self):
        source_root = self.root / 'source'
        work_dir = self.root / 'work'
        source_root.mkdir()
        work_dir.mkdir()
        directories = {}

        async def spawn(*command, cwd, **kwargs):
            directories[command[0]] = cwd
            raise FileNotFoundError(command[0])

        with patch.object(service.asyncio, 'create_subprocess_exec', side_effect=spawn):
            for name in ('joern', 'semgrep'):
                result, _ = await service.run_scanner(name, source_root, work_dir)
                self.assertEqual(result['status'], 'failed')
        self.assertEqual(directories, {'joern-scan': str(work_dir), 'semgrep': str(source_root)})


class SettingsTests(unittest.TestCase):
    def test_scanner_process_limits_override_defaults(self):
        self.assertEqual(service.scanner_process_limits(''), {'trivy': 1, 'joern': 1})
        self.assertEqual(service.scanner_process_limits('trivy=2, semgrep=1'), {'trivy': 2, 'joern': 1, 'semgrep': 1})
        self.assertEqual(service.scanner_process_limits('joern=0'), {'trivy': 1})
        for invalid in ('trivy', 'unknown=1', 'trivy=-1', 'trivy=x'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                service.scanner_process_limits(invalid)

    def test_positive_int_settings_reject_zero_and_default_when_empty(self):
        with patch.dict(os.environ, {'SCAN_CONCURRENCY': '0'}), self.assertRaises(ValueError):
            service.positive_int_setting('SCAN_CONCURRENCY', 1)
        with patch.dict(os.environ, {'SCAN_CONCURRENCY': ''}):
            self.assertEqual(service.positive_int_setting('SCAN_CONCURRENCY', 1), 1)


if __name__ == '__main__':
    unittest.main()
