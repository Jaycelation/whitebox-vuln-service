import asyncio
import copy
import json
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

import app as service
import whitebox_evidence as evidence

NOWHERE = Path('/nonexistent-source-root')
SOURCES = {
    'views.py': (
        'import yaml\n'
        'from django.http import HttpResponse\n'
        '\n'
        'def ping(request):\n'
        '    host = request.GET["host"]\n'
        '    return run(host)\n'
        '\n'
        '@login_required\n'
        'def admin_ping(request):\n'
        '    host = request.GET["host"]\n'
        '    return run(host)\n'
    ),
    'requirements.txt': 'django==2.2.0\nrequests==2.19.0\npyyaml==5.1\n',
}


def dataflow_finding(line, vuln_class='command-injection', confidence='high'):
    finding = service.make_finding(
        tool='dataflow', category='sast', severity='critical', title=f'{vuln_class} flow', rule_id=f'dataflow.python.{vuln_class}',
        path='views.py', line=line, confidence=confidence, source_root=NOWHERE,
    )
    finding['trace'] = [{'kind': 'source', 'path': 'views.py', 'line': line - 1, 'detail': 'Request input'},
                        {'kind': 'sink', 'path': 'helpers.py', 'line': 3, 'detail': 'Used as an OS command'}]
    return finding


def dependency_finding(package, ecosystem='PyPI', symbols=None, vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'):
    finding = service.make_finding(
        tool='osv-scanner', category='dependency', severity='high', title=f'{package} advisory', rule_id=f'GHSA-{package}',
        path='requirements.txt', package=package, package_version='1.0', source_root=NOWHERE,
    )
    finding.update(ecosystem=ecosystem, advisory_cvss={'vector': vector, 'score': 7.5, 'source': 'ghsa'}, affected_symbols=symbols or [])
    return finding


class CvssTests(unittest.TestCase):
    def test_reference_scores(self):
        cases = {
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N': 7.5,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N': 6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N': 7.2,
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H': 8.8, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N': 5.9,
            'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H': 7.8, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H': 9.9,
            'CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N': 1.6, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': 10.0,
            'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H': 8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N': 0.0,
            'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N': 4.3,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(evidence.cvss31_base_score(vector), expected)
        self.assertEqual([evidence.cvss_rating(value) for value in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)],
                         ['none', 'low', 'medium', 'medium', 'high', 'high', 'critical'])
        with self.assertRaises(ValueError):
            evidence.cvss31_base_score('CVSS:3.1/AV:N')


class CodeContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_login_markers_are_scoped_to_the_entry_function(self):
        self.write('v.py', '@login_required\ndef other(request):\n    pass\n\n\ndef lab(request):\n'
                           '    if request.user.is_authenticated:\n        name = request.POST["n"]\n\n\n'
                           '@app.route("/p")\n@login_required\ndef guarded(request):\n    q = request.GET["q"]\n\n\n'
                           'def public(request):\n    q = request.GET["q"]\n')
        self.write('C.java', 'class C {\n    @PreAuthorize("hasRole(\'ADMIN\')")\n    @GetMapping("/x")\n'
                             '    public String x(@RequestParam String q) {\n        return run(q);\n    }\n}\n')
        self.assertIn('is_authenticated', evidence.authentication_marker(self.root, 'v.py', 8))
        self.assertIn('@login_required (v.py:12)', evidence.authentication_marker(self.root, 'v.py', 14))
        self.assertIsNone(evidence.authentication_marker(self.root, 'v.py', 18))
        self.assertIn('@PreAuthorize', evidence.authentication_marker(self.root, 'C.java', 5))
        self.write('m.py', '# @login_required\n@csrf_exempt\ndef api(request):\n    x = request.POST["e"]\n')
        self.assertIsNone(evidence.authentication_marker(self.root, 'm.py', 4))

    def test_import_index_maps_packages_to_imports(self):
        self.write('app/main.py', 'import yaml\nfrom django.http import HttpResponse\n')
        self.write('web/index.js', "const axios = require('axios');\nimport { x } from '@scope/lib/sub';\n")
        self.write('svc/main.go', 'import (\n\t"github.com/gin-gonic/gin/binding"\n)\n')
        self.write('src/A.java', 'import com.fasterxml.jackson.databind.ObjectMapper;\n')
        self.write('src/a.php', '<?php\nuse GuzzleHttp\\Client;\n')
        self.write('src/A.cs', 'using Newtonsoft.Json;\n')
        self.write('app/a.rb', "require 'nokogiri'\n")
        index = evidence.ImportIndex(self.root)
        self.assertEqual(index.usages('PyPI', 'PyYAML'), ['app/main.py:1'])
        self.assertEqual(index.usages('PyPI', 'Django'), ['app/main.py:2'])
        self.assertEqual(index.usages('PyPI', 'requests'), [])
        self.assertEqual(index.usages('npm', 'axios'), ['web/index.js:1'])
        self.assertEqual(index.usages('npm', '@scope/lib'), ['web/index.js:2'])
        self.assertEqual(index.usages('Go', 'github.com/gin-gonic/gin'), ['svc/main.go:2'])
        self.assertEqual(index.usages('Maven', 'com.fasterxml.jackson.core:jackson-databind'), ['src/A.java:1'])
        self.assertEqual(index.usages('Maven', 'org.springframework:spring-web'), [])
        self.assertEqual(index.usages('Packagist', 'guzzlehttp/guzzle'), ['src/a.php:2'])
        self.assertEqual(index.usages('NuGet', 'Newtonsoft.Json'), ['src/A.cs:1'])
        self.assertEqual(index.usages('RubyGems', 'nokogiri'), ['app/a.rb:1'])


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative, text in SOURCES.items():
            (self.root / relative).write_text(text)

    def assessed(self, *findings):
        evidence.assess(list(findings), self.root)
        return findings

    def test_version_match_alone_is_never_scored(self):
        unused, imported = self.assessed(dependency_finding('requests'), dependency_finding('PyYAML'))
        self.assertEqual(unused['evidence']['level'], 'unverified')
        self.assertIn('never imports', unused['evidence']['items'][0])
        self.assertEqual(imported['evidence']['level'], 'present')
        self.assertIn('views.py:1', imported['evidence']['items'][0])
        self.assertIsNone(unused['cvss'])
        self.assertIsNone(imported['cvss'])

    def test_dependency_with_a_called_vulnerable_function_is_scored_from_the_advisory(self):
        called, not_called = self.assessed(dependency_finding('PyYAML', symbols=['yaml.run']),
                                           dependency_finding('PyYAML', symbols=['yaml.full_load']))
        self.assertEqual(called['evidence']['level'], 'reachable')
        self.assertEqual((called['cvss']['score'], called['cvss']['basis']), (7.5, 'advisory'))
        self.assertEqual(not_called['evidence']['level'], 'present')
        self.assertIsNone(not_called['cvss'])

    def test_traced_flow_is_scored_and_login_lowers_privileges(self):
        public, admin = self.assessed(dataflow_finding(6), dataflow_finding(11))
        self.assertEqual(public['evidence']['level'], 'reachable')
        self.assertEqual((public['cvss']['score'], public['cvss']['basis']), (9.8, 'static-trace'))
        self.assertIn('PR:N', public['cvss']['vector'])
        self.assertIn('/PR:L/', admin['cvss']['vector'])
        self.assertEqual(admin['cvss']['score'], 8.8)
        self.assertIn('@login_required', admin['cvss']['reasons'][1])

    def test_patterns_secrets_and_flagged_findings_are_not_scored(self):
        pattern = service.make_finding(tool='semgrep', category='sast', severity='high', title='x', rule_id='r', path='views.py', line=5, source_root=NOWHERE)
        secret = service.make_finding(tool='gitleaks', category='secret', severity='high', title='s', rule_id='k', path='views.py', line=5, source_root=NOWHERE)
        flagged = dataflow_finding(6)
        flagged['fp_check'] = {'verdict': 'likely_false_positive', 'reasons': ['In test code or fixtures.'], 'duplicate_of': None}
        self.assessed(pattern, secret, flagged)
        self.assertEqual([item['evidence']['level'] for item in (pattern, secret, flagged)], ['present', 'present', 'present'])
        self.assertTrue(all(item['cvss'] is None for item in (pattern, secret, flagged)))
        self.assertIn('never uses found credentials', secret['evidence']['items'][0])

    def test_duplicates_share_the_canonical_evidence(self):
        canonical = dependency_finding('PyYAML', symbols=['yaml.run'])
        copy_ = dependency_finding('PyYAML', symbols=['yaml.run'])
        copy_['id'] = 'f' * 24
        copy_['fp_check'] = {'verdict': 'duplicate', 'reasons': [], 'duplicate_of': canonical['id']}
        self.assessed(canonical, copy_)
        self.assertEqual(copy_['evidence']['level'], 'reachable')
        self.assertEqual(copy_['cvss'], canonical['cvss'])
        self.assertTrue(copy_['evidence']['items'][0].startswith('Duplicate of'))

    def test_triage_confirms_overrides_rejects_and_clears(self):
        (pattern,) = self.assessed(service.make_finding(tool='semgrep', category='sast', severity='high', title='x',
                                                        rule_id='dataflow.python.sql-injection', path='views.py', line=5, source_root=NOWHERE))
        self.assertIsNone(pattern['cvss'])
        pattern['triage_status'] = 'confirmed'
        evidence.apply_triage(pattern)
        self.assertEqual((pattern['evidence']['level'], pattern['cvss']['score']), ('confirmed', 9.8))
        pattern['triage_cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'
        evidence.apply_triage(pattern)
        self.assertEqual((pattern['cvss']['score'], pattern['cvss']['basis']), (7.2, 'reviewer'))
        pattern['triage_status'] = 'false_positive'
        evidence.apply_triage(pattern)
        self.assertEqual((pattern['evidence']['level'], pattern['cvss']), ('false_positive', None))
        pattern['triage_status'] = 'needs_review'
        evidence.apply_triage(pattern)
        self.assertEqual((pattern['evidence']['level'], pattern['cvss']), ('present', None))


class ParserTests(unittest.TestCase):
    def test_trivy_prefers_the_severity_source_vector(self):
        item = {'SeveritySource': 'nvd', 'CVSS': {
            'ghsa': {'V3Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N', 'V3Score': 4.3},
            'nvd': {'V3Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'V3Score': 9.8}}}
        self.assertEqual(service.trivy_advisory_cvss(item)['source'], 'nvd')
        self.assertIsNone(service.trivy_advisory_cvss({'CVSS': {'nvd': {'V2Vector': 'AV:N/AC:L/Au:N/C:P/I:P/A:P'}}}))

    def test_osv_symbols_and_vector(self):
        vulnerability = {
            'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'}],
            'affected': [{'ecosystem_specific': {'imports': [{'path': 'golang.org/x/net/html', 'symbols': ['Parse', 'ParseFragment']}]}}],
        }
        self.assertEqual(service.osv_advisory_cvss(vulnerability)['score'], 7.5)
        self.assertEqual(service.osv_affected_symbols(vulnerability), ['Parse', 'ParseFragment'])


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        data = Path(self.temporary.name)
        for name, value in {'DATA_DIR': data, 'DB_PATH': data / 'scans.sqlite3', 'JOB_QUEUE': asyncio.Queue(maxsize=10),
                            'RECOVERING': False, 'API_KEY': ''}.items():
            patcher = patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        service.initialize_storage()

    async def scan(self, findings, project='shop'):
        scan_id = uuid.uuid4().hex
        directory = service.job_dir(scan_id)
        directory.mkdir(parents=True)
        with zipfile.ZipFile(directory / 'source.zip', 'w') as archive:
            for relative, text in SOURCES.items():
                archive.writestr(f'project/{relative}', text)
        with service.connect_db() as db:
            db.execute('INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) VALUES (?, ?, ?, ?, ?, ?, 1)',
                       (scan_id, project, 'queued', service.utc_now(), service.utc_now(), json.dumps(['semgrep'])))
        result = ({'name': 'semgrep', 'status': 'completed'}, copy.deepcopy(findings))
        with patch.object(service, 'run_scanner', new=AsyncMock(return_value=result)):
            await service.process_scan(scan_id)
        return scan_id, service.get_report(scan_id)

    async def patch_finding(self, scan_id, finding_id, body):
        transport = httpx.ASGITransport(app=service.app)
        async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
            return await client.patch(f'/api/scans/{scan_id}/findings/{finding_id}', json=body)

    async def test_scan_summary_filters_and_sarif(self):
        scan_id, report = await self.scan([dataflow_finding(6), dependency_finding('requests')])
        self.assertEqual(report['summary']['evidence']['reachable'], 1)
        self.assertEqual(report['summary']['evidence']['unverified'], 1)
        self.assertEqual(report['summary']['cvss']['critical'], 1)
        scored = service.get_report(scan_id, evidence='reachable,confirmed')
        self.assertEqual([f['tool'] for f in scored['findings']], ['dataflow'])
        sarif = service.findings_to_sarif(scan_id, report, report['findings'])
        results = {result['ruleId']: result for run in sarif['runs'] for result in run['results']}
        self.assertEqual(results['dataflow.python.command-injection']['properties']['security-severity'], '9.8')
        self.assertNotIn('security-severity', results['GHSA-requests']['properties'])

    async def test_reviewer_vector_is_validated_stored_and_carried_over(self):
        scan_id, report = await self.scan([dependency_finding('requests')])
        target = report['findings'][0]['id']
        bad = await self.patch_finding(scan_id, target, {'status': 'confirmed', 'cvss_vector': 'CVSS:3.1/AV:N'})
        self.assertEqual(bad.status_code, 422)
        vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
        good = await self.patch_finding(scan_id, target, {'status': 'confirmed', 'note': 'requests used via vendored client', 'cvss_vector': vector})
        self.assertEqual(good.status_code, 200, good.text)
        confirmed = service.get_report(scan_id)['findings'][0]
        self.assertEqual((confirmed['evidence']['level'], confirmed['cvss']['score'], confirmed['cvss']['basis']), ('confirmed', 5.9, 'reviewer'))
        self.assertEqual(service.get_scan(scan_id)['summary']['evidence']['confirmed'], 1)
        _, later = await self.scan([dependency_finding('requests')])
        self.assertEqual((later['findings'][0]['evidence']['level'], later['findings'][0]['cvss']['vector']), ('confirmed', vector))


if __name__ == '__main__':
    unittest.main()
