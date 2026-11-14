"""Offline unit/integration tests (no LLM, no network).  Run:  python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "evaluator"))

import yaml  # noqa: E402
from common import load_config, load_manifest, load_vectors  # noqa: E402
import conversation_log  # noqa: E402
from stream_telemetry import mcp_tool_name, parse_stream  # noqa: E402
import io_harness  # noqa: E402
import cost_evaluator  # noqa: E402

SAMPLE = "CWE190_Integer_Overflow__int_fscanf_multiply_01"


def gcc_build(src: Path, out: Path):
    subprocess.run(["gcc", "-O2", "-w", str(src), "-o", str(out)], check=True)


class DatasetTests(unittest.TestCase):
    def test_manifest_and_vectors(self):
        cfg = load_config()
        samples = load_manifest(cfg)
        self.assertEqual(len(samples), cfg["dataset"]["sample_count"])
        for s in samples:
            v = load_vectors(cfg, s["sample_id"])
            self.assertEqual(len(v["curated"]), cfg["evaluation"]["io_equivalence"]["curated_cases_per_file"])
            self.assertEqual(len(v["fuzz"]), cfg["evaluation"]["io_equivalence"]["differential_fuzz_cases"])


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {**os.environ, "FAKE_AGY_RECON": ""}
        out = subprocess.run([sys.executable, str(ROOT / "tests" / "fake_agy.py")], cwd=self.tmp,
                             capture_output=True, text=True, env={**os.environ}).stdout
        self.lines = out.splitlines()

    def test_metrics(self):
        m = parse_stream(self.lines, "rea")
        self.assertEqual(m["turns"], 3)
        self.assertEqual(m["tokens"]["input_uncached"], 1900)
        self.assertEqual(m["tokens"]["input_cached"], 3400)
        self.assertEqual(m["tokens"]["reasoning"], 330)
        self.assertEqual(m["tokens"]["output"], 520 - 330)          # thinking is a subset of output_tokens
        self.assertEqual(m["tokens"]["peak_context"], 2500)
        self.assertEqual(m["mcp_calls"], 2)
        self.assertEqual(m["mcp_calls_by_tool"], {"open_binary": 1, "binary_overview": 1})
        self.assertEqual(m["mcp_payload_bytes"], 200)
        self.assertEqual(m["other_tool_calls"], 2)
        self.assertAlmostEqual(m["latency"]["llm_time_sec"], 6.0)

    def test_mcp_name_variants(self):
        self.assertEqual(mcp_tool_name({"tool_name": "mcp_rea_procedure_pseudo_code"}, "rea"), "procedure_pseudo_code")
        self.assertEqual(mcp_tool_name({"tool_name": "procedure_pseudo_code"}, "rea"), "procedure_pseudo_code")
        self.assertIsNone(mcp_tool_name({"tool_name": "run_command"}, "rea"))
        self.assertEqual(mcp_tool_name({"tool_name": "call_mcp_tool",
                                        "tool_info": {"parameters": {"ServerName": "rea", "ToolName": "list_procedures"}}}, "rea"), "list_procedures")
        self.assertIsNone(mcp_tool_name({"tool_name": "call_mcp_tool",
                                         "tool_info": {"parameters": {"ServerName": "other", "ToolName": "list_procedures"}}}, "rea"))


class IOHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config()
        cls.tmp = Path(tempfile.mkdtemp())
        cls.src = ROOT / "dataset" / "normalized_src" / f"{SAMPLE}.c"
        cls.chal = cls.tmp / "chal"
        gcc_build(cls.src, cls.chal)
        cls.vec = load_vectors(cls.cfg, SAMPLE)

    def test_identical_passes(self):
        res = io_harness.grade(self.src, self.chal, self.vec, self.cfg)
        self.assertTrue(res["io_passed"], res["failures"])
        self.assertEqual(res["io_tests_total"], 65)

    def test_wrong_logic_partial_accuracy(self):
        bad = self.tmp / "bad.c"
        bad.write_text(self.src.read_text().replace("data * 2", "data * 3"))
        res = io_harness.grade(bad, self.chal, self.vec, self.cfg)
        self.assertFalse(res["io_passed"])
        self.assertTrue(res["gate1"]["passed"])
        self.assertLess(res["io_tests_passed"], res["io_tests_total"])
        self.assertGreater(res["io_accuracy"], 0.0)

    def test_forbidden_constructs_rejected(self):
        for payload in ('int main(){system("ls");return 0;}', 'int main(){__asm__("nop");return 0;}',
                        'int main(){execl("/bin/sh","sh",0);return 0;}',
                        'int main(){FILE*f=fopen("./chal","r");return f!=0;}'):
            f = self.tmp / "x.c"
            f.write_text(payload)
            res = io_harness.grade(f, self.chal, self.vec, self.cfg)
            self.assertFalse(res["gate1"]["passed"], payload)
            self.assertFalse(res["io_passed"])

    def test_comment_mentions_do_not_trigger(self):
        v = io_harness.static_sanitize('/* system() is not used */ int main(){puts("popen");return 0;}',
                                       self.cfg["evaluation"]["io_equivalence"]["forbidden_tokens"])
        self.assertEqual(v, [])

    def test_compile_error_and_missing(self):
        f = self.tmp / "broken.c"
        f.write_text("int main( {")
        res = io_harness.grade(f, self.chal, self.vec, self.cfg)
        self.assertFalse(res["gate1"]["compile_ok"])
        res = io_harness.grade(self.tmp / "nope.c", self.chal, self.vec, self.cfg)
        self.assertFalse(res["io_passed"])


class CostEvaluatorTests(unittest.TestCase):
    def test_ocm_ecsr(self):
        cfg = load_config()
        tmp = Path(tempfile.mkdtemp())

        def put(sc, sid, passed, tokens, mcp, passed_tests=None):
            d = tmp / sc / sid
            d.mkdir(parents=True)
            (d / "telemetry.json").write_text(json.dumps({
                "scenario": sc, "sample_id": sid, "io_passed": passed, "io_tests_passed": 65 if passed else 30,
                "io_tests_total": 65, "tokens": tokens, "mcp_calls": mcp, "wall_time_sec": 10}))

        base = {"input_uncached": 1000, "input_cached": 0, "reasoning": 500, "output": 500, "peak_context": 2000}
        s1 = {"input_uncached": 3000, "input_cached": 0, "reasoning": 1500, "output": 1500, "peak_context": 6000}
        put("S0_Baseline", "a", True, base, 4)
        put("S0_Baseline", "b", True, base, 4)
        put("S1_Flatten", "a", True, s1, 12)
        put("S1_Flatten", "b", False, s1, 12)
        pricing = cfg["evaluation"]["cost_telemetry"]["pricing_per_1m_tokens_usd"]
        summary = cost_evaluator.aggregate(cost_evaluator.load_runs(tmp, pricing), cfg)
        s1m = summary["scenarios"]["S1_Flatten"]
        self.assertAlmostEqual(s1m["ocm_all"]["tokens_mean"], 3.0)
        self.assertAlmostEqual(s1m["ocm_pass_only"]["tokens_mean"], 3.0)
        self.assertAlmostEqual(s1m["ocm_all"]["tools_mean"], 3.0)
        cost = (3000 * 0.15 + 3000 * 0.60) / 1e6
        self.assertAlmostEqual(s1m["ecsr_usd"], 2 * cost / 1)          # two runs, one success
        self.assertAlmostEqual(s1m["ecsr_tokens"], 2 * 6000 / 1)
        self.assertEqual(summary["scenarios"]["S0_Baseline"]["ecsr_usd"], 2 * (1000 * 0.15 + 1000 * 0.6) / 1e6 / 2)
        self.assertIn("S1_Flatten", cost_evaluator.markdown_table(summary))


class HookGuardTests(unittest.TestCase):
    def run_hook(self, payload):
        p = subprocess.run([sys.executable, str(ROOT / "runner" / "hook_guard.py"), "--jail", "/tmp/run_t",
                            "--log", os.devnull, "--mcp-server", "rea"], input=json.dumps(payload),
                           capture_output=True, text=True)
        return json.loads(p.stdout)["decision"]

    def cmd(self, c):
        return {"tool_name": "run_command", "tool_info": {"parameters": {"CommandLine": c}}}

    def rea_mcp(self, tool, args):
        return {"tool_name": "call_mcp_tool", "tool_info": {"parameters": {"ServerName": "rea", "ToolName": tool, "Arguments": args}}}

    def test_decisions(self):
        # Shell disassemblers must be blocked to enforce REA exclusivity
        self.assertEqual(self.run_hook(self.cmd("objdump -d chal | head -50")), "deny")
        self.assertEqual(self.run_hook(self.cmd("readelf -h ./chal")), "deny")
        self.assertEqual(self.run_hook(self.cmd("strings ./chal")), "deny")
        self.assertEqual(self.run_hook(self.cmd("gdb -batch ./chal")), "deny")
        # Allowed compile / execution inside jail
        self.assertEqual(self.run_hook(self.cmd("gcc -O2 reconstructed.c -o recon_bin")), "allow")
        self.assertEqual(self.run_hook(self.cmd("./chal")), "allow")
        # Sandbox boundary checks
        self.assertEqual(self.run_hook(self.cmd("cat ../x")), "deny")
        self.assertEqual(self.run_hook(self.cmd("ls /home")), "deny")
        self.assertEqual(self.run_hook(self.cmd("printenv")), "deny")
        self.assertEqual(self.run_hook(self.cmd("ls /tmp/run_t")), "allow")
        # Reading REA MCP tool schemas and REA skill files is allowed
        self.assertEqual(self.run_hook({"tool_name": "read_file", "tool_info": {"parameters": {
            "Path": "/home/arch/.gemini/antigravity-cli/mcp/rea/open_binary.json"}}}), "allow")
        self.assertEqual(self.run_hook({"tool_name": "read_file", "tool_info": {"parameters": {
            "Path": "/home/arch/.gemini/config/skills/reverse-engineer-anything/SKILL.md"}}}), "allow")
        # REA calls
        self.assertEqual(self.run_hook(self.rea_mcp("open_binary", {"path": "./chal"})), "deny")
        self.assertEqual(self.run_hook(self.rea_mcp("open_binary", {"path": "/tmp/run_t/chal"})), "allow")
        self.assertEqual(self.run_hook(self.rea_mcp("open_binary", {"path": "/etc/shadow"})), "deny")
        self.assertEqual(self.run_hook(self.rea_mcp("list_procedures", {})), "allow")
        self.assertEqual(self.run_hook(self.rea_mcp("procedure_pseudo_code", {"procedure": "0x1010c0"})), "allow")


@unittest.skipUnless((ROOT / "build" / "S0_Baseline" / SAMPLE / "chal").exists(), "run builder first")
class PipelineSmokeTests(unittest.TestCase):
    def _write_fake_cfg(self, tmp: Path) -> Path:
        cfg = load_config()
        cfg["paths"]["results_dir"] = str(tmp / "results")
        cfg["agent_runtime"]["agy_binary"] = str(ROOT / "tests" / "fake_agy.py")
        cfg["agent_runtime"]["sandbox"]["jail_root"] = str(tmp)
        cfg_path = tmp / "exp.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg))
        return cfg_path

    def test_orchestrator_with_fake_agent(self):
        tmp = Path(tempfile.mkdtemp())
        cfg_path = self._write_fake_cfg(tmp)
        env = {**os.environ, "FAKE_AGY_RECON": str(ROOT / "dataset" / "normalized_src" / f"{SAMPLE}.c")}
        for sc in ("S0_Baseline", "S3_Combined"):
            subprocess.run([sys.executable, str(ROOT / "runner" / "orchestrator.py"), "--config", str(cfg_path),
                            "--scenarios", sc, "--samples", SAMPLE, "--no-mcp"], check=True, env=env,
                           capture_output=True, text=True)
        subprocess.run([sys.executable, str(ROOT / "evaluator" / "cost_evaluator.py"), "--config", str(cfg_path),
                        "--results", str(tmp / "results")], check=True, capture_output=True, text=True)
        tel = json.loads((tmp / "results" / "S3_Combined" / SAMPLE / "telemetry.json").read_text())
        self.assertTrue(tel["io_passed"])
        self.assertEqual(tel["io_tests_total"], 65)
        self.assertEqual(tel["mcp_calls"], 2)
        self.assertEqual(tel["tokens"]["input_cached"], 3400)
        self.assertTrue((tmp / "results" / "S3_Combined" / SAMPLE / "conversation_log.md").exists())
        self.assertTrue((tmp / "results" / "simulator.html").exists())
        self.assertFalse(list(tmp.glob("run_*")), "jail must be cleaned up")

    def test_unlimited_and_override_limits(self):
        tmp = Path(tempfile.mkdtemp())
        cfg_path = self._write_fake_cfg(tmp)
        env = {**os.environ, "FAKE_AGY_RECON": str(ROOT / "dataset" / "normalized_src" / f"{SAMPLE}.c")}
        subprocess.run([sys.executable, str(ROOT / "runner" / "orchestrator.py"), "--config", str(cfg_path),
                        "--scenarios", "S0_Baseline", "--samples", SAMPLE, "--no-mcp", "--unlimited"],
                       check=True, env=env, capture_output=True, text=True)
        m = json.loads((tmp / "results" / "S0_Baseline" / SAMPLE / "run_metrics.json").read_text())
        self.assertEqual(m["terminated_reason"], "completed")
        self.assertIsNone(m["limits"]["max_turns"])
        self.assertIsNone(m["limits"]["max_mcp_calls"])
        self.assertIsNone(m["limits"]["timeout_seconds"])

        # Explicit 0 overrides also resolve to None (infinite)
        subprocess.run([sys.executable, str(ROOT / "runner" / "orchestrator.py"), "--config", str(cfg_path),
                        "--scenarios", "S0_Baseline", "--samples", SAMPLE, "--no-mcp",
                        "--max-turns", "0", "--max-mcp-calls", "0", "--timeout", "0"],
                       check=True, env=env, capture_output=True, text=True)
        m2 = json.loads((tmp / "results" / "S0_Baseline" / SAMPLE / "run_metrics.json").read_text())
        self.assertEqual(m2["terminated_reason"], "completed")
        self.assertIsNone(m2["limits"]["max_turns"])


class ConversationLogTests(unittest.TestCase):
    def test_snapshot_and_render_with_transcript(self):
        tmp = Path(tempfile.mkdtemp())
        brain = tmp / "brain"
        cid = "conv-1234"
        tdir = brain / cid / ".system_generated" / "logs"
        tdir.mkdir(parents=True)
        (tdir / "transcript_full.jsonl").write_text("\n".join([
            json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "Analyze ./chal"}),
            json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "created_at": "2026-11-14T00:00:00Z",
                        "thinking": "Inspecting main function via REA.", "content": "",
                        "tool_calls": [{"name": "call_mcp_tool", "args": {"ServerName": "rea",
                                       "ToolName": "procedure_pseudo_code", "Arguments": {"procedure": "0x1010c0"}}}]}),
            json.dumps({"step_index": 2, "type": "GENERIC", "status": "DONE",
                        "content": "Created At: 2026-11-14\n" + json.dumps({
                            "evidence_id": "ev_1", "operation": "procedure_pseudo_code",
                            "provider": {"id": "ghidra"}, "confidence": "observed",
                            "normalized_result": "int main(void) {\n  return 0;\n}"})}),
        ]) + "\n", encoding="utf-8")

        run_dir = tmp / "run"
        run_dir.mkdir()
        (run_dir / "session_stream.jsonl").write_text("\n".join([
            json.dumps({"event": "init", "conversation_id": cid, "init": {"cwd": "/tmp/jail"}}),
            json.dumps({"event": "step_update", "step_update": {"conversation_id": cid, "step_index": 1,
                        "state": "DONE", "step_type": "agent_response", "duration_seconds": 1.2,
                        "usage": {"input_tokens": 100, "cache_read_tokens": 50, "thinking_tokens": 20, "output_tokens": 30}}}),
            json.dumps({"event": "step_update", "step_update": {"conversation_id": cid, "step_index": 2,
                        "state": "DONE", "step_type": "tool", "tool_name": "call_mcp_tool", "duration_seconds": 0.4,
                        "tool_info": {"name": "call_mcp_tool", "parameters": {"ServerName": "rea",
                                      "ToolName": "procedure_pseudo_code", "Arguments": {"procedure": "0x1010c0"}}}}}),
        ]) + "\n", encoding="utf-8")
        (run_dir / "hook_audit.jsonl").write_text(
            json.dumps({"ts": 1.0, "tool": "call_mcp_tool",
                        "args": {"ServerName": "rea", "ToolName": "procedure_pseudo_code"},
                        "decision": "allow", "reason": None}) + "\n",
            encoding="utf-8",
        )

        copied = conversation_log.snapshot_transcript(run_dir, brain_root=brain)
        self.assertIsNotNone(copied)
        self.assertTrue((run_dir / "transcript_full.jsonl").exists())

        out_md = conversation_log.render_conversation_log(run_dir)
        text = out_md.read_text(encoding="utf-8")
        self.assertIn("Analyze ./chal", text)
        self.assertIn("Inspecting main function via REA.", text)
        self.assertIn("rea:procedure_pseudo_code", text)
        self.assertIn("int main(void)", text)
        self.assertIn("Hook Guard Audit (`allow=1`, `deny=0`)", text)


if __name__ == "__main__":
    unittest.main()
