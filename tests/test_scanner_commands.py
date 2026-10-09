import unittest
from pathlib import Path

import app as service


class ScannerCommandTests(unittest.TestCase):
    def command(self, name):
        return service.scanner_command(name, Path('/src'), Path('/work/out.json'))

    def test_semgrep_does_not_use_auto_config_with_metrics_off(self):
        # Semgrep refuses `--config auto` when metrics are off ("Cannot create auto
        # config when metrics are off"), which failed every Semgrep run.
        command = self.command('semgrep')
        self.assertIn('--metrics=off', command)
        config = command[command.index('--config') + 1]
        self.assertNotEqual(config, 'auto')

    def test_scanners_keep_telemetry_off(self):
        self.assertIn('--metrics=off', self.command('semgrep'))
        self.assertIn('--disable-telemetry', self.command('trivy'))


if __name__ == '__main__':
    unittest.main()


class OsvNoManifestTests(unittest.IsolatedAsyncioTestCase):
    async def run_fake_osv(self, message):
        import sys
        import tempfile
        from unittest.mock import patch
        script = f'import sys; sys.stderr.write({message!r}); sys.exit(128)'
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            with patch.object(service, 'DATA_DIR', work), \
                 patch.object(service, 'scanner_command', return_value=[sys.executable, '-c', script]):
                result, findings = await service.run_scanner('osv-scanner', work, work)
        return result, findings

    async def test_project_without_manifests_is_not_a_failure(self):
        result, findings = await self.run_fake_osv('No package sources found, --help for usage information.\n')
        self.assertEqual((result['status'], result['error'], findings), ('completed', None, []))

    async def test_other_exit_128_errors_still_fail(self):
        result, _ = await self.run_fake_osv('fatal: database download failed\n')
        self.assertEqual(result['status'], 'failed')
