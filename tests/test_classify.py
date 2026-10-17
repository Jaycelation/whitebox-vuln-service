import unittest
from pathlib import Path

import app as service
import whitebox_classify as classify

import test_false_positives

NOWHERE = Path('/nonexistent-source-root')


def semgrep_result(path, line, cwe, owasp=None, end_line=None, rule='python.lang.security.audit.subprocess-shell-true'):
    metadata = {'cwe': cwe, 'confidence': 'MEDIUM'}
    if owasp is not None:
        metadata['owasp'] = owasp
    return {'check_id': rule, 'path': path, 'start': {'line': line}, 'end': {'line': end_line or line},
            'extra': {'message': 'Found shell=True', 'severity': 'ERROR', 'metadata': metadata}}


def dataflow_finding(path, line, vuln_class='command-injection'):
    data = {'findings': [{'class': vuln_class, 'language': 'python', 'path': path, 'line': line,
                          'trace': [{'kind': 'source', 'path': path, 'line': 1, 'detail': 'request.args'},
                                    {'kind': 'sink', 'path': path, 'line': line, 'detail': 'os.system'}]}]}
    return service.parse_dataflow(data, NOWHERE)[0]


class NormalizeTests(unittest.TestCase):
    def test_cwe_ids_from_every_scanner_format(self):
        self.assertEqual(classify.normalize_cwes(['CWE-78: Improper Neutralization', 'cwe_89', 79, '22']),
                         ['CWE-78', 'CWE-89', 'CWE-79', 'CWE-22'])
        self.assertEqual(classify.normalize_cwes('CWE-078'), ['CWE-78'])
        self.assertEqual(classify.normalize_cwes([None, True, {}]), [])

    def test_owasp_ids(self):
        self.assertEqual(classify.normalize_owasp(['A03:2021 - Injection', 'A1:2017 - Injection', 'a03:2021']),
                         ['A03:2021', 'A01:2017'])

    def test_scanner_owasp_prefers_the_2021_edition(self):
        finding = service.parse_semgrep({'results': [semgrep_result('a.py', 3, ['CWE-78'], ['A01:2017 - Injection', 'A03:2021 - Injection'])]}, NOWHERE)[0]
        self.assertEqual(finding['classification']['owasp'], ['A03:2021'])
        self.assertEqual(finding['classification']['owasp_source'], 'scanner')
        self.assertEqual(finding['classification']['class'], 'command-injection')
        self.assertEqual(finding['cwe'], 'CWE-78')

    def test_owasp_is_derived_from_the_cwe_when_the_scanner_gives_none(self):
        finding = service.parse_semgrep({'results': [semgrep_result('a.py', 3, ['CWE-918: SSRF'])]}, NOWHERE)[0]
        self.assertEqual(finding['classification']['owasp'], ['A10:2021'])
        self.assertEqual(finding['classification']['owasp_names'], ['Server-Side Request Forgery'])
        self.assertEqual(finding['classification']['owasp_source'], 'cwe-mapping')

    def test_category_defaults(self):
        secret = service.parse_gitleaks([{'RuleID': 'github-pat', 'File': 'a.py', 'StartLine': 1}], NOWHERE)[0]
        self.assertEqual(secret['classification']['cwe'], ['CWE-798'])
        self.assertEqual(secret['classification']['owasp'], ['A07:2021'])
        self.assertEqual(secret['classification']['class'], 'hardcoded-secret')
        trivy = service.parse_trivy({'Results': [{'Target': 'requirements.txt', 'Type': 'pip', 'Vulnerabilities': [
            {'VulnerabilityID': 'CVE-2023-1', 'PkgName': 'django', 'InstalledVersion': '2.2', 'Severity': 'HIGH', 'CweIDs': ['CWE-89']}],
            'Misconfigurations': [{'ID': 'DS002', 'Severity': 'HIGH', 'Title': 'Root user'}]}]}, NOWHERE)
        dependency, misconfiguration = trivy
        # A vulnerable component is A06 first, then what the weakness maps to.
        self.assertEqual(dependency['classification']['owasp'], ['A06:2021', 'A03:2021'])
        self.assertEqual(dependency['classification']['class'], 'sql-injection')
        self.assertEqual(misconfiguration['classification']['owasp'], ['A05:2021'])

    def test_dataflow_class_is_kept(self):
        finding = dataflow_finding('app.py', 5, 'template-injection')
        self.assertEqual(finding['classification']['class'], 'template-injection')
        self.assertEqual(finding['classification']['cwe'], ['CWE-79'])
        self.assertEqual(finding['cwe'], 'CWE-79')


class SeverityTests(unittest.TestCase):
    def test_vendor_severity_words(self):
        for raw, expected in {'MODERATE': 'medium', 'Important': 'high', 'negligible': 'low', 'ERROR': 'high', 'bogus': 'unknown'}.items():
            self.assertEqual(service.normalize_severity(raw), expected, raw)

    def test_osv_ghsa_moderate_is_medium(self):
        self.assertEqual(service.osv_severity({'database_specific': {'severity': 'MODERATE'}}), 'medium')

    def test_osv_severity_from_a_cvss_vector(self):
        vulnerability = {'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]}
        self.assertEqual(service.osv_severity(vulnerability), 'critical')
        vulnerability = {'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'}]}
        self.assertEqual(service.osv_severity(vulnerability), 'low')

    def test_osv_cwe_ids_are_classified(self):
        data = {'results': [{'source': {'path': 'go.mod'}, 'packages': [{'package': {'name': 'x', 'version': '1', 'ecosystem': 'Go'},
                 'vulnerabilities': [{'id': 'GO-1', 'database_specific': {'severity': 'MODERATE', 'cwe_ids': ['CWE-22']}}]}]}]}
        finding = service.parse_osv(data, NOWHERE)[0]
        self.assertEqual(finding['severity'], 'medium')
        self.assertEqual(finding['classification']['cwe'], ['CWE-22'])


class CrossToolDuplicateTests(unittest.TestCase):
    def checked(self, findings):
        service.check_false_positives(findings, NOWHERE)
        return findings

    def test_semgrep_match_on_a_traced_sink_is_a_duplicate_of_the_trace(self):
        # Semgrep runs first, but the traced finding is the canonical one.
        semgrep = service.parse_semgrep({'results': [semgrep_result('app.py', 4, ['CWE-78'], end_line=6)]}, NOWHERE)[0]
        traced = dataflow_finding('app.py', 5)
        self.checked([semgrep, traced])
        self.assertEqual(semgrep['fp_check']['verdict'], 'duplicate')
        self.assertEqual(semgrep['fp_check']['duplicate_of'], traced['id'])
        self.assertEqual(traced['fp_check']['verdict'], 'needs_review')

    def test_xss_rule_matches_the_dataflow_template_class(self):
        semgrep = service.parse_semgrep({'results': [semgrep_result('app.py', 5, ['CWE-79'])]}, NOWHERE)[0]
        traced = dataflow_finding('app.py', 5, 'template-injection')
        self.checked([semgrep, traced])
        self.assertEqual(semgrep['fp_check']['duplicate_of'], traced['id'])

    def test_different_weakness_or_line_is_not_a_duplicate(self):
        other_cwe = service.parse_semgrep({'results': [semgrep_result('app.py', 5, ['CWE-327'])]}, NOWHERE)[0]
        other_line = service.parse_semgrep({'results': [semgrep_result('app.py', 9, ['CWE-78'])]}, NOWHERE)[0]
        no_cwe = service.parse_semgrep({'results': [semgrep_result('app.py', 5, [])]}, NOWHERE)[0]
        traced = dataflow_finding('app.py', 5)
        self.checked([other_cwe, other_line, no_cwe, traced])
        for finding in (other_cwe, other_line, no_cwe):
            self.assertEqual(finding['fp_check']['verdict'], 'needs_review')

    def test_duplicate_shares_the_traced_evidence_and_score(self):
        import tempfile
        import whitebox_evidence
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').write_text('import os\n\n\n\nos.system(request.args["host"])\n\n')
            semgrep = service.parse_semgrep({'results': [semgrep_result('app.py', 5, ['CWE-78'])]}, root)[0]
            traced = dataflow_finding('app.py', 5)
            findings = [semgrep, traced]
            service.check_false_positives(findings, root)
            whitebox_evidence.assess(findings, root)
        self.assertEqual(semgrep['evidence']['level'], 'reachable')
        self.assertEqual(semgrep['cvss']['score'], traced['cvss']['score'])


class SummaryTests(unittest.TestCase):
    def test_unique_counts_skip_duplicates(self):
        semgrep = service.parse_semgrep({'results': [semgrep_result('app.py', 5, ['CWE-78'])]}, NOWHERE)[0]
        traced = dataflow_finding('app.py', 5)
        secret = service.parse_gitleaks([{'RuleID': 'github-pat', 'File': 'a.py', 'StartLine': 1}], NOWHERE)[0]
        findings = [semgrep, traced, secret]
        service.check_false_positives(findings, NOWHERE)
        summary = service.summarize(findings, [])
        self.assertEqual(summary['total_findings'], 3)
        self.assertEqual(summary['unique_findings'], 2)
        self.assertEqual(summary['severity']['high'] + summary['severity']['critical'], 3)
        self.assertEqual(summary['severity_unique'], {'critical': 1, 'high': 1, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0})
        self.assertEqual(summary['by_category'], {'sast': 1, 'secret': 1, 'dependency': 0, 'misconfiguration': 0})
        self.assertEqual(summary['classification']['owasp'], {'A03:2021': 1, 'A07:2021': 1})
        self.assertEqual(summary['classification']['cwe'], {'CWE-78': 1, 'CWE-798': 1})
        self.assertEqual(summary['classification']['vuln_class'], {'command-injection': 1, 'hardcoded-secret': 1})


class ClassificationFilterTests(unittest.IsolatedAsyncioTestCase):
    # Reuse the scan harness without re-running the triage tests.
    harness = test_false_positives.TriageTests
    setUp, scan, request = harness.setUp, harness.scan, harness.request

    async def test_report_filters_by_cwe_and_owasp(self):
        scan_id, report = await self.scan()
        secrets = service.get_report(scan_id, cwe='798')
        self.assertEqual({f['category'] for f in secrets['findings']}, {'secret'})
        self.assertEqual(secrets['filter']['matched'], 3)
        components = service.get_report(scan_id, owasp='a06:2021')
        self.assertEqual(components['filter']['matched'], 4)
        self.assertEqual(report['summary']['classification']['owasp']['A06:2021'], 2)
        bad = await self.request('GET', f'/api/scans/{scan_id}/report', params={'cwe': 'injection'})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(bad.json()['detail']['invalid'], ['injection'])


if __name__ == '__main__':
    unittest.main()
