"""Deployment contracts: real tool dispatch and controller CLI, no LLM calls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

class DeploymentContracts(unittest.TestCase):
    def test_separate_agent_stores(self):
        from agent.tools import dispatch
        from agent.tools.datasource import data_dir
        from agent.durable import CheckpointStore, InvestigationCheckpoint
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            evidence = root / 'evidence'; evidence.mkdir()
            with patch.dict(os.environ, {'FK_DATA_DIR': str(evidence),
                    'FK_AGENT_STATE_ROOT': str(root / 'state'), 'FK_AGENT_AUDIT_ROOT': str(root / 'audit')}):
                # An unknown tool still requires a durable denial audit.
                self.assertIn('error', dispatch('unknown_tool', {}))
                CheckpointStore().save(InvestigationCheckpoint('run', 'case', 'start', {}))
                self.assertEqual(list(evidence.iterdir()), [])
                self.assertTrue(list((root / 'audit').rglob('governance_audit.jsonl')))
                self.assertTrue(list((root / 'state').rglob('run.json')))
                self.assertEqual(data_dir(), evidence)

    @unittest.skipUnless(os.geteuid() == 0, 'requires root to drop to deployment UID')
    def test_read_only_evidence_as_deployment_uid(self):
        from agent.tools import dispatch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o755)
            for name in ('evidence', 'release', 'state', 'audit'):
                path = root / name; path.mkdir()
                if name in ('state', 'audit'):
                    try:
                        os.chown(path, 10001, 10001)
                    except OSError as exc:
                        self.skipTest("host UID mapping unavailable: " + str(exc))
                else:
                    path.chmod(0o555)
            with patch.dict(os.environ, {'FK_DATA_DIR': str(root / 'evidence'),
                    'FK_AGENT_STATE_ROOT': str(root / 'state'),
                    'FK_AGENT_AUDIT_ROOT': str(root / 'audit'),
                    'FK_RUNTIME_BUNDLE_DIR': str(root / 'release')}):
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setgroups([]); os.setgid(10001); os.setuid(10001)
                        result = dispatch('capability_registry', {})
                        assert 'error' not in result, result
                        try:
                            (root / 'evidence' / 'forbidden').write_text('x')
                        except PermissionError:
                            os._exit(0)
                        os._exit(2)
                    except BaseException:
                        os._exit(3)
                self.assertEqual(os.waitpid(pid, 0)[1], 0)

    def test_controller_entrypoint(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'auth.json').write_text('{}')
            args = [sys.executable, '-m', 'agent.control_plane', '--store', str(root / 'journal.json'),
                    '--credentials', str(root / 'auth.json'), '--scope', 'tenant:a/app:app']
            missing = subprocess.run(args, input='', capture_output=True, text=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('--compute-capacity', missing.stderr)
            (root / 'capacity.json').write_text('{}')
            args += ['--compute-capacity', str(root / 'capacity.json')]
            bad = subprocess.run(args, input='', capture_output=True, text=True)
            self.assertIn('capacity envelope required', bad.stderr)
            (root / 'capacity.json').write_text(json.dumps(dict(target_qps=1, cpu_cores=1,
                max_utilization=.5, max_rss_bytes=1000000, max_p99_ms=50)))
            ready = subprocess.run(args, input='{"operation":"INVALID"}', capture_output=True, text=True)
            self.assertIn('unknown operation', ready.stderr)

if __name__ == '__main__': unittest.main()
