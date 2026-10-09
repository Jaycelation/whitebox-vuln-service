import asyncio
import copy
import io
import json
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

import app as service
import whitebox_mcp as adapter

NOWHERE = Path('/nonexistent-source-root')

SOURCES = {
    'src/config.py': 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    'src/settings.py': 'TOKEN = os.environ["DEPLOY_TOKEN"]\n',
    'src/real.py': 'TOKEN = "ghp_Zx81kq2Lw9RtYp4Vb7Nc3Md6Fh1Js5Ga0Ke8"\n',
    'src/run.py': 'import subprocess\nsubprocess.call(cmd, shell=True)  # nosec B602\nsubprocess.call(other, shell=True)\n',
    'tests/test_api.py': 'import subprocess\nsubprocess.call(cmd, shell=True)\n',
    'node_modules/lib/index.js': 'eval(input)\n',
    'requirements.txt': 'django==2.2.0\n',
}


def finding(tool, category, rule, path, line=None, **extra):
    return service.make_finding(
        tool=tool, category=category, severity='high', title=rule, rule_id=rule,
        path=path, line=line, source_root=NOWHERE, **extra,
    )


def dependency(tool, rule, aliases, version='2.2.0', path='requirements.txt'):
    return finding(tool, 'dependency', rule, path, package='Django',
                   package_version=version, aliases=aliases)


def sample_findings():
    return {
        'placeholder': finding('gitleaks', 'secret', 'aws-access-token', 'src/config.py', 1),
        'environment': finding('gitleaks', 'secret', 'generic-api-key', 'src/settings.py', 1),
        'real_secret': finding('gitleaks', 'secret', 'github-pat', 'src/real.py', 1),
        'suppressed': finding('semgrep', 'sast', 'subprocess-shell-true', 'src/run.py', 2),
        'unsuppressed': finding('semgrep', 'sast', 'subprocess-shell-true', 'src/run.py', 3),
        'test_code': finding('semgrep', 'sast', 'subprocess-shell-true', 'tests/test_api.py', 2),
        'vendored': finding('semgrep', 'sast', 'eval-detected', 'node_modules/lib/index.js', 1),
        'trivy_cve': dependency('trivy', 'CVE-2019-1', ['GHSA-aaaa']),
        'osv_pysec': dependency('osv-scanner', 'PYSEC-2019-1', ['CVE-2019-1', 'GHSA-aaaa']),
        'osv_ghsa': dependency('osv-scanner', 'GHSA-aaaa', ['CVE-2019-1']),
        'other_version': dependency('osv-scanner', 'PYSEC-2019-1', ['CVE-2019-1'], version='3.2.0', path='requirements-dev.txt'),
    }


def write_sources(root):
    for relative, text in SOURCES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'project'
        write_sources(self.root)

    def checked(self):
        findings = sample_findings()
        service.check_false_positives(list(findings.values()), self.root)
        return findings

    def test_path_kinds(self):
        cases = {
            'tests/unit/a.py': 'test', 'pkg/test_views.py': 'test', 'web/app.spec.ts': 'test',
            'src/FooTest.java': 'test', 'docs/setup.md': 'example', 'config/.env.example': 'example',
            'node_modules/x/y.js': 'vendored', 'static/app.min.js': 'generated',
            'src/app.py': None, 'src/latest.py': None, 'src/contest.py': None,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(service.path_kind(path), expected)

    def test_verdicts_and_reasons(self):
        findings = self.checked()
        verdicts = {name: item['fp_check']['verdict'] for name, item in findings.items()}
        self.assertEqual(verdicts, {
            'placeholder': 'likely_false_positive',
            'environment': 'likely_false_positive',
            'real_secret': 'needs_review',
            'suppressed': 'likely_false_positive',
            'unsuppressed': 'needs_review',
            'test_code': 'likely_false_positive',
            'vendored': 'needs_review',
            'trivy_cve': 'needs_review',
            'osv_pysec': 'duplicate',
            'osv_ghsa': 'duplicate',
            'other_version': 'needs_review',
        })
        self.assertIn("'nosec'", findings['suppressed']['fp_check']['reasons'][0])
        self.assertIn('third-party', findings['vendored']['fp_check']['reasons'][0])

    def test_duplicates_point_at_the_first_report(self):
        findings = self.checked()
        canonical = findings['trivy_cve']['id']
        self.assertIsNone(findings['trivy_cve']['fp_check']['duplicate_of'])
        self.assertEqual(findings['osv_pysec']['fp_check']['duplicate_of'], canonical)
        self.assertEqual(findings['osv_ghsa']['fp_check']['duplicate_of'], canonical)
        self.assertIsNone(findings['other_version']['fp_check']['duplicate_of'])

    def test_secret_reported_by_two_scanners_is_one_finding(self):
        gitleaks = finding('gitleaks', 'secret', 'github-pat', 'src/real.py', 1)
        trivy = finding('trivy', 'secret', 'github-pat', 'src/real.py', 1)
        elsewhere = finding('trivy', 'secret', 'github-pat', 'src/settings.py', 1)
        service.check_false_positives([gitleaks, trivy, elsewhere], self.root)
        self.assertEqual(trivy['fp_check']['verdict'], 'duplicate')
        self.assertEqual(trivy['fp_check']['duplicate_of'], gitleaks['id'])
        self.assertIsNone(gitleaks['fp_check']['duplicate_of'])
        self.assertIsNone(elsewhere['fp_check']['duplicate_of'])

    def test_code_match_key_survives_moved_lines(self):
        before = finding('semgrep', 'sast', 'rule', 'src/run.py', 2)
        after = finding('semgrep', 'sast', 'rule', 'src/run.py', 40)
        line = 'subprocess.call(cmd,   shell=True)'
        self.assertEqual(service.finding_match_key(before, line), service.finding_match_key(after, ' ' + line))
        self.assertNotEqual(service.finding_match_key(before, line), service.finding_match_key(before, 'other()'))

    def test_secret_match_key_ignores_the_line_content(self):
        secret = finding('gitleaks', 'secret', 'github-pat', 'src/real.py', 1)
        self.assertEqual(service.finding_match_key(secret, 'TOKEN = "a"'), service.finding_match_key(secret, 'TOKEN = "b"'))
        moved = finding('gitleaks', 'secret', 'github-pat', 'src/real.py', 2)
        self.assertNotEqual(service.finding_match_key(secret), service.finding_match_key(moved))

    def test_source_lines_stay_inside_the_source_root(self):
        (self.root.parent / 'outside.txt').write_text('secret\n')
        lines = service.SourceLines(self.root)
        self.assertIsNone(lines.get('../outside.txt', 1))
        self.assertEqual(lines.get('src/settings.py', 1), SOURCES['src/settings.py'].strip())
        self.assertIsNone(lines.get('src/settings.py', 99))


class TriageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name)
        for name, value in {
            'DATA_DIR': self.data,
            'DB_PATH': self.data / 'scans.sqlite3',
            'JOB_QUEUE': asyncio.Queue(maxsize=10),
            'RECOVERING': False,
            'API_KEY': '',
        }.items():
            patcher = patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        service.initialize_storage()

    async def scan(self, project='shop', sources=SOURCES, findings=None):
        scan_id = uuid.uuid4().hex
        directory = service.job_dir(scan_id)
        directory.mkdir(parents=True)
        with zipfile.ZipFile(directory / 'source.zip', 'w') as archive:
            for relative, text in sources.items():
                archive.writestr(f'project/{relative}', text)
        with service.connect_db() as db:
            db.execute(
                'INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) '
                'VALUES (?, ?, ?, ?, ?, ?, 1)',
                (scan_id, project, 'queued', service.utc_now(), service.utc_now(), json.dumps(['semgrep'])),
            )
        items = copy.deepcopy(list((findings or sample_findings()).values()))
        with patch.object(service, 'run_scanner', new=AsyncMock(return_value=({'name': 'semgrep', 'status': 'completed'}, items))):
            await service.process_scan(scan_id)
        return scan_id, service.get_report(scan_id)

    async def request(self, method, path, **kwargs):
        transport = httpx.ASGITransport(app=service.app)
        async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
            return await client.request(method, path, **kwargs)

    def by_rule(self, report, rule, path=None):
        return next(f for f in report['findings'] if f['rule_id'] == rule and (path is None or f['path'] == path))

    async def test_scan_report_has_checks_and_counts_without_source_text(self):
        scan_id, report = await self.scan()
        self.assertEqual(report['summary']['fp_check'], {'needs_review': 5, 'likely_false_positive': 4, 'duplicate': 2})
        self.assertEqual(report['summary']['triage']['needs_review'], 11)
        self.assertTrue(all('match_key' in f and 'fp_check' in f for f in report['findings']))
        stored = (service.job_dir(scan_id) / 'report.json').read_text()
        for secret_text in ('ghp_Zx81kq2', 'AKIAIOSFODNN7EXAMPLE', 'DEPLOY_TOKEN'):
            self.assertNotIn(secret_text, stored)
        self.assertEqual(service.get_scan(scan_id)['summary']['fp_check']['duplicate'], 2)

    async def test_triage_updates_duplicates_report_summary_and_sarif(self):
        scan_id, report = await self.scan()
        duplicate = self.by_rule(report, 'GHSA-aaaa')
        response = await self.request('PATCH', f'/api/scans/{scan_id}/findings/{duplicate["id"]}',
                                      json={'status': 'false_positive', 'note': 'Django admin is not deployed.'})
        self.assertEqual(response.status_code, 200, response.text)
        group = {
            self.by_rule(report, 'CVE-2019-1')['id'],
            self.by_rule(report, 'PYSEC-2019-1', 'requirements.txt')['id'],
            duplicate['id'],
        }
        self.assertEqual(set(response.json()['updated']), group)

        updated = service.get_report(scan_id, triage_status='false_positive')
        self.assertEqual({f['id'] for f in updated['findings']}, group)
        self.assertTrue(all(f['triage_note'] == 'Django admin is not deployed.' for f in updated['findings']))
        self.assertEqual(updated['summary']['triage']['false_positive'], 3)
        self.assertEqual(service.get_scan(scan_id)['summary']['triage']['false_positive'], 3)

        sarif = (await self.request('GET', f'/api/scans/{scan_id}/report.sarif')).json()
        results = [r for run in sarif['runs'] for r in run['results']]
        suppressed = [r for r in results if r.get('suppressions')]
        self.assertEqual(len(suppressed), 3)
        self.assertEqual(suppressed[0]['suppressions'][0]['justification'], 'Django admin is not deployed.')
        # Heuristic verdicts alone never suppress.
        self.assertFalse(any(r.get('suppressions') for r in results if r['properties']['fp_verdict'] == 'likely_false_positive'))

    async def test_triage_rejects_bad_input(self):
        scan_id, report = await self.scan()
        target = report['findings'][0]['id']
        bad_status = await self.request('PATCH', f'/api/scans/{scan_id}/findings/{target}', json={'status': 'ignore'})
        self.assertEqual(bad_status.status_code, 422)
        missing = await self.request('PATCH', f'/api/scans/{scan_id}/findings/{"0" * 24}', json={'status': 'confirmed'})
        self.assertEqual(missing.status_code, 404)

    async def test_report_filters_by_fp_verdict(self):
        scan_id, _ = await self.scan()
        actionable = service.get_report(scan_id, fp_verdict='needs_review')
        self.assertEqual(actionable['filter']['matched'], 5)
        self.assertTrue(all(f['fp_check']['verdict'] == 'needs_review' for f in actionable['findings']))
        bad = await self.request('GET', f'/api/scans/{scan_id}/report', params={'fp_verdict': 'nope'})
        self.assertEqual(bad.status_code, 422)

    async def test_decisions_carry_over_to_later_scans_of_the_same_project(self):
        scan_id, report = await self.scan()
        target = next(f for f in report['findings'] if f['path'] == 'src/run.py' and f['line'] == 3)
        response = await self.request('PATCH', f'/api/scans/{scan_id}/findings/{target["id"]}',
                                      json={'status': 'false_positive', 'note': 'cmd is a constant.'})
        self.assertEqual(response.status_code, 200, response.text)

        # Two lines were added above the code, so the finding moves from line 3 to line 5.
        moved_sources = dict(SOURCES, **{'src/run.py': '# a\n# b\n' + SOURCES['src/run.py']})
        moved = {'moved': finding('semgrep', 'sast', 'subprocess-shell-true', 'src/run.py', 5)}
        _, later = await self.scan(sources=moved_sources, findings=moved)
        carried = later['findings'][0]
        self.assertEqual((carried['triage_status'], carried['triage_source']), ('false_positive', 'earlier_scan'))
        self.assertEqual(carried['triage_note'], 'cmd is a constant.')

        _, other_project = await self.scan(project='billing', sources=moved_sources, findings=moved)
        self.assertEqual(other_project['findings'][0]['triage_status'], 'needs_review')

        cleared = await self.request('PATCH', f'/api/scans/{scan_id}/findings/{target["id"]}', json={'status': 'needs_review'})
        self.assertEqual(cleared.status_code, 200)
        _, after_clear = await self.scan(sources=moved_sources, findings=moved)
        self.assertEqual(after_clear['findings'][0]['triage_status'], 'needs_review')


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_triage_tool_sends_the_decision(self):
        request = AsyncMock(return_value={'updated': ['a' * 24]})
        with patch.object(adapter, '_api_request', request):
            await adapter.whitebox_triage_finding('b' * 32, 'a' * 24, 'false_positive', 'not reachable')
        request.assert_awaited_once_with(
            'PATCH', f'/api/scans/{"b" * 32}/findings/{"a" * 24}',
            json={'status': 'false_positive', 'note': 'not reachable'},
        )
        with self.assertRaises(ValueError):
            await adapter.whitebox_triage_finding('b' * 32, 'a' * 24, 'ignore')

    async def test_report_tool_passes_fp_filters(self):
        request = AsyncMock(side_effect=[{'status': 'completed'}, {'findings': [], 'summary': {}}])
        with patch.object(adapter, '_api_request', request):
            await adapter.whitebox_get_report('b' * 32, fp_verdict='needs_review')
        self.assertEqual(request.await_args_list[1].kwargs, {'params': {'fp_verdict': 'needs_review'}})


if __name__ == '__main__':
    unittest.main()
