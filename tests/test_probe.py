"""End-to-end tests: real spawns against the example servers in examples/.

These run the actual doctor probe against a real healthy server, a real
crash-on-import server, a hanging server, and a nonexistent command —
the four verdict classes a doctor must distinguish. Uses unittest only.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_fleet_doctor import configs  # noqa: E402
from mcp_fleet_doctor.probe import (  # noqa: E402
    VER_CRASHED, VER_CMD_MISSING, VER_NO_TOOLS, VER_OK, VER_UNRESPONSIVE,
    probe as probe_fn,
)

EXAMPLES = ROOT / "examples"
OK = str(EXAMPLES / "ok_server.py")
MISSING_DEP = str(EXAMPLES / "missing_dep_server.py")
HANGING = str(EXAMPLES / "hanging_server.py")
PY = sys.executable  # absolute python — mirrors the doctor's advice!


def _spec(name, cmd, args):
    return configs.ServerSpec(name=name, command=cmd, args=args,
                              env=configs.build_env(None)[0].copy())



class HealthyServer(unittest.TestCase):
    def test_ok_lists_tools(self):
        r = probe_fn(_spec("ok", PY, [OK]))
        self.assertEqual(r.verdict, VER_OK, r.detail)
        self.assertEqual(r.tools, 2)
        self.assertIn("echo", r.detail)


class BrokenServers(unittest.TestCase):
    def test_delayed_missing_dependency_detected(self):
        r = probe_fn(_spec("dep", PY, [MISSING_DEP]), handshake_timeout=8)
        self.assertEqual(r.verdict, VER_CRASHED, r.detail)
        self.assertIn("some_module_that_does_not_exist", (r.missing_module or ""))
        self.assertIn("module", r.detail)

    def test_hanging_server_classified(self):
        r = probe_fn(_spec("hang", PY, [HANGING]),
                  handshake_timeout=3, startup_timeout=2, call_timeout=2)
        self.assertEqual(r.verdict, VER_UNRESPONSIVE, r.detail)

    def test_command_not_found(self):
        r = probe_fn(_spec("ghost", "this-binary-does-not-exist-9z", []))
        self.assertEqual(r.verdict, VER_CMD_MISSING, r.detail)


class ConfigParsing(unittest.TestCase):
    def test_json_matrix(self):
        cc = configs.load_client("file", EXAMPLES / "claude_desktop_config.json")
        self.assertIsNotNone(cc)
        names = {s.name for s in cc.servers}
        self.assertEqual(names, {"example-ok", "example-missing-dep", "example-hanging", "example-not-installed"})
        loaded = configs._load_data(EXAMPLES / "claude_desktop_config.json")

    def test_yaml_without_pyyaml(self):
        import builtins
        real_import = builtins.__import__

        def no_yaml(name, *a, **k):
            if name == "yaml":
                raise ImportError("simulated: pyyaml not installed")
            return real_import(name, *a, **k)
        builtins.__import__ = no_yaml
        try:
            cc = configs.load_client("file", EXAMPLES / "hermes_config.yaml")
        finally:
            builtins.__import__ = real_import
        self.assertIsNotNone(cc)
        self.assertEqual({s.name: s.command for s in cc.servers},
                         {"example-ok": "python3", "example-missing-dep": "python3", "example-hanging": "python3"})
        ok = [s for s in cc.servers if s.name == "example-ok"][0]
        self.assertEqual(ok.args, ["examples/ok_server.py"])

    def test_static_checks_flag_bare_python(self):
        spec = configs.ServerSpec(name="b", command="python3", args=[])
        warn = configs.static_checks(spec)
        self.assertTrue(any("bare interpreter" in w for w in warn), str(warn))

    def test_static_checks_missing_env_placeholder(self):
        # env referencing a variable that does not exist anywhere
        spec = configs.ServerSpec(name="h", command="echo", args=[],
                                  env={"PATH2X": "${LLM_API_KEY_UNSET_X}"})
        env, missing = configs.build_env(spec.env)
        spec.env = env
        self.assertEqual(missing, ["LLM_API_KEY_UNSET_X"])


class StaticBarePython(unittest.TestCase):
    def test_bare_python_flagged(self):
        spec = configs.ServerSpec(name="raw", command="python3", args=[])
        self.assertTrue(any("bare interpreter" in w for w in configs.static_checks(spec)))


class DisabledServers(unittest.TestCase):
    def test_run_skips_disabled(self):
        from mcp_fleet_doctor import cli
        cc = configs.ClientConfig(client="file", path=EXAMPLES / "claude_desktop_config.json")
        spec = configs.ServerSpec(name="off", command="true", args=[],
                                  raw={"enabled": False})
        cc.servers = [spec,
                      configs.ServerSpec(name="ghost", command="definitely-not-here-88", args=[])]
        results, disabled = cli._run(cc)
        self.assertEqual(disabled, ["off"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, VER_CMD_MISSING)


if __name__ == "__main__":
    unittest.main()
