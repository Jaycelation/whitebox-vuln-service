import asyncio
import io
import json
import tempfile
import threading
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException, UploadFile

import app as service
import whitebox_mcp as adapter


def source_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('project/main.py', 'print("hello")\n')
    return buffer.getvalue()


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, value in {
            'DATA_DIR': self.root,
            'DB_PATH': self.root / 'scans.sqlite3',
            'JOB_QUEUE': asyncio.Queue(maxsize=10),
            'RECOVERING': False,
        }.items():
            patcher = patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        service.initialize_storage()
        self.inventory = patch.object(service, 'scanner_inventory', return_value=[
            {'name': 'semgrep', 'available': True},
        ])
        self.inventory.start()
        self.addCleanup(self.inventory.stop)

    def seed(self, status='queued', scanners=None):
        scan_id = uuid.uuid4().hex
        directory = service.job_dir(scan_id)
        directory.mkdir(parents=True)
        payload = source_zip()
        (directory / 'source.zip').write_bytes(payload)
        with service.connect_db() as db:
            db.execute(
                'INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (scan_id, 'test', status, service.utc_now(), service.utc_now(),
                 json.dumps(scanners or ['semgrep']), len(payload)),
            )
        return scan_id

    async def test_concurrent_uploads_return_503_without_orphan(self):
        service.JOB_QUEUE = asyncio.Queue(maxsize=1)
        both_validating = asyncio.Event()
        arrived = 0

        async def validate(function, *args):
            nonlocal arrived
            result = function(*args)
            arrived += 1
            if arrived == 2:
                both_validating.set()
            await both_validating.wait()
            return result

        uploads = [UploadFile(file=io.BytesIO(source_zip()), filename='source.zip') for _ in range(2)]
        with patch.object(service, 'complete_thread_work', side_effect=validate):
            results = await asyncio.gather(*(
                service.create_scan(upload, 'semgrep', 'test') for upload in uploads
            ), return_exceptions=True)
        accepted = [result for result in results if isinstance(result, dict)]
        rejected = [result for result in results if isinstance(result, HTTPException)]
        self.assertEqual(len(accepted), 1)
        self.assertEqual([result.status_code for result in rejected], [503])
        with service.connect_db() as db:
            ids = [row['id'] for row in db.execute('SELECT id FROM scans')]
        self.assertEqual(ids, [accepted[0]['id']])
        self.assertEqual([entry.name for entry in (self.root / 'jobs').iterdir()], ids)
        self.assertTrue(all(upload.file.closed for upload in uploads))

    async def test_cancelled_upload_is_removed(self):
        reading = asyncio.Event()

        async def slow_read(*args):
            reading.set()
            await asyncio.Event().wait()

        upload = UploadFile(file=io.BytesIO(source_zip()), filename='source.zip')
        with patch.object(upload, 'read', side_effect=slow_read):
            task = asyncio.create_task(service.create_scan(upload, 'semgrep', 'test'))
            await reading.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(list((self.root / 'jobs').iterdir()), [])
        self.assertEqual(service.list_scans()['scans'], [])
        self.assertTrue(upload.file.closed)

    async def test_cancelled_scanner_preserves_upload_for_retry(self):
        scan_id = self.seed()
        running = asyncio.Event()

        async def scanner(*args):
            running.set()
            await asyncio.Event().wait()

        with patch.object(service, 'run_scanner', side_effect=scanner):
            task = asyncio.create_task(service.process_scan(scan_id))
            await running.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        directory = service.job_dir(scan_id)
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'queued')
        self.assertTrue((directory / 'source.zip').is_file())
        self.assertFalse((directory / 'source').exists())
        self.assertFalse((directory / 'work').exists())
        self.assertEqual(service.recover_and_prune(), [scan_id])
        result = ({'name': 'semgrep', 'status': 'completed'}, [])
        with patch.object(service, 'run_scanner', new=AsyncMock(return_value=result)):
            await service.process_scan(scan_id)
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'completed')
        self.assertFalse((directory / 'source.zip').exists())
        self.assertEqual(service.get_report(scan_id)['summary']['scanners_completed'], 1)

    async def test_cancelled_extraction_finishes_before_cleanup(self):
        scan_id = self.seed()
        started = threading.Event()
        release = threading.Event()
        original = service.extract_zip

        def extraction(*args):
            started.set()
            if not release.wait(5):
                raise RuntimeError('test did not release extraction')
            return original(*args)

        with patch.object(service, 'extract_zip', side_effect=extraction):
            task = asyncio.create_task(service.process_scan(scan_id))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 5))
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        directory = service.job_dir(scan_id)
        self.assertFalse((directory / 'source').exists())
        self.assertTrue((directory / 'source.zip').is_file())

    async def test_restart_recovers_running_plus_ten_queued_jobs(self):
        ids = [self.seed('running')] + [self.seed() for _ in range(10)]
        stale = service.job_dir(ids[0])
        (stale / 'source').mkdir()
        (stale / 'source' / 'incomplete').write_text('stale')
        (stale / 'work').mkdir()
        (stale / 'work' / 'semgrep.json').write_text('stale')
        processed = []
        recovered = asyncio.Event()

        async def process(scan_id):
            self.assertFalse((service.job_dir(scan_id) / 'source').exists())
            self.assertFalse((service.job_dir(scan_id) / 'work').exists())
            processed.append(scan_id)
            service.update_scan(scan_id, status='completed')
            if len(processed) == len(ids):
                recovered.set()

        with patch.object(service, 'process_scan', side_effect=process):
            async with service.lifespan(service.app):
                await asyncio.wait_for(recovered.wait(), timeout=5)
                await asyncio.wait_for(service.JOB_QUEUE.join(), timeout=5)
        self.assertCountEqual(processed, ids)
        self.assertEqual(len(processed), 11)
        self.assertTrue(all(service.get_scan_row(scan_id)['status'] == 'completed' for scan_id in ids))

    async def test_large_recovery_backlog_does_not_block_startup(self):
        ids = [self.seed() for _ in range(12)]
        running = asyncio.Event()

        async def process(scan_id):
            running.set()
            await asyncio.Event().wait()

        with patch.object(service, 'process_scan', side_effect=process):
            context = service.lifespan(service.app)
            await asyncio.wait_for(context.__aenter__(), timeout=1)
            try:
                await asyncio.wait_for(running.wait(), timeout=1)
                self.assertTrue(service.RECOVERING)
                # Recovery has priority even if a slot becomes available.
                queued = service.JOB_QUEUE.get_nowait()
                service.JOB_QUEUE.task_done()
                upload = UploadFile(file=io.BytesIO(source_zip()))
                try:
                    with self.assertRaises(HTTPException) as rejected:
                        await service.create_scan(upload, 'semgrep', 'new')
                    self.assertEqual(rejected.exception.status_code, 503)
                finally:
                    service.JOB_QUEUE.put_nowait(queued)
                    await upload.close()
                self.assertTrue(all(service.get_scan_row(scan_id)['status'] == 'queued' for scan_id in ids))
            finally:
                await context.__aexit__(None, None, None)
        self.assertFalse(service.RECOVERING)

    async def test_recovery_marks_missing_upload_failed(self):
        scan_id = self.seed()
        (service.job_dir(scan_id) / 'source.zip').unlink()
        self.assertEqual(service.recover_and_prune(), [])
        self.assertEqual(service.get_scan_row(scan_id)['status'], 'failed')

    async def test_report_status_reflects_scanner_outcomes(self):
        for statuses, expected in [
            (['completed', 'completed'], 'completed'),
            (['completed', 'failed'], 'partial'),
            (['failed', 'timed_out'], 'failed'),
        ]:
            with self.subTest(statuses=statuses):
                scan_id = self.seed(scanners=['semgrep', 'trivy'])
                results = [({'name': name, 'status': status}, [])
                           for name, status in zip(['semgrep', 'trivy'], statuses)]
                with patch.object(service, 'run_scanner', new=AsyncMock(side_effect=results)):
                    await service.process_scan(scan_id)
                self.assertEqual(service.get_scan_row(scan_id)['status'], expected)
                self.assertEqual(len(service.get_report(scan_id)['scanners']), 2)
                self.assertFalse((service.job_dir(scan_id) / 'source.zip').exists())

    async def test_api_accepts_valid_zip_and_rejects_invalid_zip(self):
        transport = httpx.ASGITransport(app=service.app)
        with patch.object(service, 'API_KEY', ''):
            async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
                for payload, expected in [(source_zip(), 202), (b'not a zip', 400)]:
                    response = await client.post('/api/scans', data={'scanners': 'semgrep'},
                                                 files={'source': ('source.zip', payload)})
                    self.assertEqual(response.status_code, expected, response.text)
        self.assertEqual(len(service.list_scans()['scans']), 1)


class ArchiveTests(unittest.TestCase):
    def test_central_directory_counts_toward_archive_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / 'repo'
            repository.mkdir()
            (repository / 'a').write_bytes(b'')
            target = root / 'upload.zip'
            # Local file header fits, but the ZIP central directory exceeds 60 B.
            def create_temp(**kwargs):
                import os
                return os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600), str(target)

            with patch.object(adapter.tempfile, 'mkstemp', side_effect=create_temp), \
                 patch.object(adapter, 'MAX_ARCHIVE_BYTES', 60):
                with self.assertRaisesRegex(ValueError, 'MAX_ARCHIVE_BYTES'):
                    adapter._create_archive(repository)
            self.assertFalse(target.exists())

    def test_archive_excludes_symlinks_and_generated_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / 'main.py').write_text('print(1)')
            (repository / 'link.py').symlink_to(repository / 'main.py')
            (repository / 'node_modules').mkdir()
            (repository / 'node_modules' / 'dependency.js').write_text('ignored')
            archive, size, count = adapter._create_archive(repository)
            try:
                self.assertEqual(count, 1)
                self.assertEqual(size, len('print(1)'))
                with zipfile.ZipFile(archive) as result:
                    self.assertEqual(result.namelist(), ['main.py'])
                self.assertEqual(len(service.validate_zip_archive(archive)), 1)
            finally:
                archive.unlink()


if __name__ == '__main__':
    unittest.main()
