import asyncio
import io
import json
import sqlite3
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


if __name__ == '__main__':
    unittest.main()
