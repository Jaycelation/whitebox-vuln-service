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
