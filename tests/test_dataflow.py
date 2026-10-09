import asyncio
import io
import json
import re
import shutil
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

import app as service
import whitebox_dataflow as dataflow

FIXTURES = Path(__file__).parent / 'fixtures' / 'dataflow'
HAS_SEMGREP = shutil.which('semgrep') is not None


def expected_flows(root):
    """(path, line, class) for every `EXPECT <class>` marker in the fixtures."""
    expected = set()
    for path in sorted(root.rglob('*')):
        if path.is_file():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                for vuln_class in re.findall(r'EXPECT ([a-z-]+)', line):
                    expected.add((path.relative_to(root).as_posix(), number, vuln_class))
    return expected


def copy_fixtures():
    # Semgrep skips files under a git checkout's tests/ directory, so scan a copy.
    directory = tempfile.TemporaryDirectory()
    target = Path(directory.name) / 'project'
    shutil.copytree(FIXTURES, target)
    return directory, target


class ParameterTests(unittest.TestCase):
    def test_parameter_names_per_language(self):
        cases = {
            'python': ('self, name: str, limit=10, *args, **kwargs', ['self', 'name', 'limit', 'args', 'kwargs']),
            'javascript': ('req, { body }, count = 1, ...rest', ['req', None, 'count', 'rest']),
            'java': ('@RequestParam("q") String query, final int page', ['query', 'page']),
            'php': ('$user_id, array $options = []', ['$user_id', '$options']),
            'go': ('w http.ResponseWriter, name string', ['w', 'name']),
            'ruby': ('target, timeout: 5, *rest', ['target', 'timeout', 'rest']),
            'csharp': ('[FromQuery] string cmd, int page = 1', ['cmd', 'page']),
        }
        for language, (text, names) in cases.items():
            with self.subTest(language=language):
                self.assertEqual(dataflow.parameter_names(language, text), names)

    def test_parameter_index_finds_the_enclosing_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo.py').write_text(
                'class Repo:\n'
                '    def find_user(self, tenant,\n'
                '                  name):\n'
                '        self.cursor.execute(name)\n'
            )
            python = dataflow.LANGUAGES['python']
            self.assertEqual(dataflow.find_parameter_index(root, python, 'repo.py', 4, 'find_user', 'name'), (2, 1))
            self.assertEqual(dataflow.find_parameter_index(root, python, 'repo.py', 4, 'find_user', 'missing'), (None, None))
            (root / 'lib.php').write_text('<?php\nfunction load($conn, $user_id) {\n  return query($user_id);\n}\n')
            php = dataflow.LANGUAGES['php']
            self.assertEqual(dataflow.find_parameter_index(root, php, 'lib.php', 3, 'load', '$user_id'), (1, 1))

    def test_call_patterns_respect_position_and_generic_names(self):
        python = dataflow.LANGUAGES['python']
        patterns = python.call_patterns('fetch_url', 0, 0, 'url')
        self.assertIn('fetch_url($X, ...)', patterns)
        self.assertIn('$RECV.fetch_url($X, ...)', patterns)
        self.assertIn('fetch_url(..., url=$X, ...)', patterns)
        self.assertIn('find_user($ARG0, $X, ...)', python.call_patterns('find_user', 1, 0, 'name'))
        # A helper called `get` must not turn every obj.get(...) into a sink.
        self.assertFalse([pattern for pattern in python.call_patterns('get', 0, 0, 'url') if pattern.startswith('$RECV')])
        php = dataflow.LANGUAGES['php']
        self.assertIn('$RECV->load_user($X, ...)', php.call_patterns('load_user', 0, 0, '$id'))


class RuleTests(unittest.TestCase):
    def test_rules_are_complete_and_serializable(self):
        summaries = {
            'wrap~python~command-injection~run_ping~0': dataflow.Summary('python', 'run_ping', 'h.py', 3, 'command-injection', 'target', 0, 0),
            'src~python~current_user': dataflow.Summary('python', 'current_user', 'v.py', 9),
        }
        rules = dataflow.build_rules(sorted(dataflow.LANGUAGES), summaries)
        json.dumps({'rules': rules})
        self.assertEqual(len({rule['id'] for rule in rules}), len(rules))
        for rule in rules:
            self.assertTrue(rule['message'] and rule['languages'])
            for sink in rule.get('pattern-sinks', []):
                self.assertIn({'focus-metavariable': '$X'}, sink['patterns'])
        flow_sources = next(rule for rule in rules if rule['id'].startswith('flow.python'))['pattern-sources']
        self.assertIn({'pattern': 'current_user(...)'}, flow_sources)
        self.assertTrue(any(rule['message'] == 'FLOW|command-injection|wrap~python~command-injection~run_ping~0' for rule in rules))

    def test_trace_follows_the_summary_chain(self):
        archive = dataflow.Summary('python', 'archive', 'helpers.py', 17, 'command-injection', 'path', 0, 0, 'base', 17)
        backup = dataflow.Summary('python', 'do_backup', 'services.py', 5, 'command-injection', 'directory', 0, 0, archive.key, 5)
        summaries = {archive.key: archive, backup.key: backup}
        flow = {'language': 'python', 'class': 'command-injection', 'hop': backup.key, 'path': 'views.py', 'line': 36, 'end_line': 36}
        finding = dataflow.build_finding(flow, summaries, {'views.py': [(30, ''), (36, '')]})
        self.assertEqual([step['kind'] for step in finding['trace']], ['source', 'call', 'parameter', 'call', 'parameter', 'sink'])
        self.assertEqual((finding['trace'][-1]['path'], finding['trace'][-1]['line']), ('helpers.py', 17))
        self.assertEqual(finding['trace'][0]['line'], 36)
        self.assertTrue(finding['interprocedural'])

    def test_direct_sink_wins_when_a_location_matches_twice(self):
        flows = [
            {'path': 'a.py', 'line': 3, 'class': 'ssrf', 'hop': 'wrap~x'},
            {'path': 'a.py', 'line': 3, 'class': 'ssrf', 'hop': 'base'},
            {'path': 'a.py', 'line': 3, 'class': 'path-traversal', 'hop': 'base'},
        ]
        self.assertEqual([flow['hop'] for flow in dataflow.dedupe_flows(flows)], ['base', 'base'])


class ServiceParserTests(unittest.TestCase):
    def test_engine_output_becomes_findings_with_trace(self):
        data = {'findings': [
            {'language': 'python', 'class': 'sql-injection', 'path': 'views.py', 'line': 51, 'end_line': 51, 'interprocedural': True,
             'trace': [{'kind': 'source', 'path': 'views.py', 'line': 51, 'detail': 'Request input'},
                       {'kind': 'sink', 'path': 'views.py', 'line': 21, 'detail': 'Used as a SQL query'}]},
            {'language': 'python', 'class': 'not-a-class', 'path': 'x.py', 'line': 1, 'trace': []},
            'garbage',
        ]}
        findings = service.parse_dataflow(data, Path('/nonexistent'))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding['tool'], finding['category'], finding['severity']), ('dataflow', 'sast', 'high'))
        self.assertEqual((finding['rule_id'], finding['confidence'], finding['cwe']), ('dataflow.python.sql-injection', 'medium', 'CWE-89'))
        self.assertEqual(finding['references'], ['https://cwe.mitre.org/data/definitions/89.html'])
        self.assertEqual([step['line'] for step in finding['trace']], [51, 21])
        self.assertIn('Used as a SQL query (views.py:21)', finding['message'])

        sarif = service.findings_to_sarif('x', {}, findings)
        flow = sarif['runs'][0]['results'][0]['codeFlows'][0]['threadFlows'][0]['locations']
        self.assertEqual([step['location']['physicalLocation']['region']['startLine'] for step in flow], [51, 21])

    def test_dataflow_is_a_default_scanner_backed_by_semgrep(self):
        self.assertIn('dataflow', service.DEFAULT_SCANNERS)
        self.assertEqual(service.SCANNER_BINARIES['dataflow'], 'semgrep')
        command = service.scanner_command('dataflow', Path('/src'), Path('/work/dataflow.json'))
        self.assertTrue(command[1].endswith('whitebox_dataflow.py'))
        self.assertEqual(command[-1], '/src')


@unittest.skipUnless(HAS_SEMGREP, 'semgrep is not installed')
class EngineIntegrationTests(unittest.TestCase):
    def test_every_language_fixture_matches_expectations_exactly(self):
        directory, root = copy_fixtures()
        self.addCleanup(directory.cleanup)
        report = dataflow.analyze(root)
        self.assertEqual(report['errors'], [])
        self.assertTrue(report['complete'])
        self.assertEqual(report['languages'], ['csharp', 'go', 'java', 'javascript', 'php', 'python', 'ruby'])
        found = {(finding['path'], finding['line'], finding['class']) for finding in report['findings']}
        expected = expected_flows(root)
        self.assertEqual(sorted(expected - found), [], 'missed flows')
        self.assertEqual(sorted(found - expected), [], 'unexpected flows')


@unittest.skipUnless(HAS_SEMGREP, 'semgrep is not installed')
class ServiceIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_reports_traced_flows(self):
        with tempfile.TemporaryDirectory() as data:
            data_dir = Path(data)
            with patch.multiple(service, DATA_DIR=data_dir, DB_PATH=data_dir / 'scans.sqlite3', JOB_QUEUE=asyncio.Queue(maxsize=10)):
                service.initialize_storage()
                scan_id = uuid.uuid4().hex
                directory = service.job_dir(scan_id)
                directory.mkdir(parents=True)
                with zipfile.ZipFile(directory / 'source.zip', 'w') as archive:
                    for path in (FIXTURES / 'python').rglob('*.py'):
                        archive.writestr(f'project/{path.relative_to(FIXTURES / "python")}', path.read_text())
                with service.connect_db() as db:
                    db.execute(
                        'INSERT INTO scans (id, name, status, created_at, updated_at, scanners_json, upload_bytes) '
                        'VALUES (?, ?, ?, ?, ?, ?, 1)',
                        (scan_id, 'flask-app', 'queued', service.utc_now(), service.utc_now(), json.dumps(['dataflow'])),
                    )
                await service.process_scan(scan_id)
                report = service.get_report(scan_id)
        self.assertEqual(report['scanners'][0]['status'], 'completed', report['scanners'])
        by_location = {(f['path'], f['line']): f for f in report['findings']}
        two_levels = by_location[('views.py', 36)]
        self.assertEqual(two_levels['rule_id'], 'dataflow.python.command-injection')
        self.assertEqual([step['path'] for step in two_levels['trace']], ['views.py', 'views.py', 'services.py', 'services.py', 'helpers.py', 'helpers.py'])
        self.assertEqual(len(report['findings']), len(expected_flows(FIXTURES / 'python')))


if __name__ == '__main__':
    unittest.main()
