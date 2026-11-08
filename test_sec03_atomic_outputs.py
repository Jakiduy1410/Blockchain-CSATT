"""Regression coverage for publishing SEC-03 outputs after a complete run."""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import compare
import run_all_attacks as runner


ROOT = Path(__file__).resolve().parent
CHART_NAMES = (
    "sec03_comparison_chart.png",
    "sec03_comparison_mutation.png",
    "sec03_comparison_bitflip.png",
)


def load_attack_module():
    requests = types.ModuleType("requests")
    requests.RequestException = type("RequestException", (Exception,), {})
    adapters = types.ModuleType("requests.adapters")
    adapters.HTTPAdapter = type("HTTPAdapter", (), {})
    modules = {"requests": requests, "requests.adapters": adapters}
    name = "sec03_atomic_test_attack"
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "Blockchain-CSATT-mldsa44" / "attack_sec03.py"
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {**modules, name: module}):
        spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def fake_plotting(fail_on_save=None):
    """Exercise compare's real staging with deterministic figure bytes."""
    saved = []

    class Axes:
        transAxes = object()

        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    class Figure:
        def tight_layout(self):
            pass

        def savefig(self, path, **kwargs):
            path = Path(path)
            saved.append(path)
            path.write_bytes(b"new comparison figure")
            if len(saved) == fail_on_save:
                raise OSError("interrupted figure write")

    matplotlib = types.ModuleType("matplotlib")
    matplotlib.use = lambda *args, **kwargs: None
    pyplot = types.ModuleType("matplotlib.pyplot")
    pyplot.subplots = lambda **kwargs: (Figure(), Axes())
    pyplot.close = lambda figure: None
    matplotlib.pyplot = pyplot
    with patch.dict(sys.modules, {
        "matplotlib": matplotlib, "matplotlib.pyplot": pyplot
    }):
        yield saved


class AttackOutputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.attack = load_attack_module()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.log = self.root / "same_name.jsonl"
        self.outputs = [self.log] + [self.log.with_suffix(suffix) for suffix in (
            ".terminal.log", ".summary.json", ".bits.png", ".mutation.png",
            ".replay.png",
        )]
        for path in self.outputs:
            path.write_bytes(b"previous complete output")
        self.args = types.SimpleNamespace(
            project_root=self.root, miner_port=5001, ports=[5001], seed=3,
            log=self.log, workers=6, settle=0, delay=0, confirm_timeout=1,
            mine=True,
        )

    def run_attack(self, interrupt=False, reject_baseline=False,
                   figure_bytes=b"new attack figure"):
        attack = self.attack
        fixtures = [{
            "sender_address": "aa", "recipient_address": "bb",
            "amount": str(index + 1), "signature": "00" * 8,
        } for index in range(1250)]
        transport = types.SimpleNamespace(
            nodes={5001: types.SimpleNamespace(protocol="http")},
            discover=lambda: None, close=lambda: None,
        )
        client = types.SimpleNamespace(
            algorithm="ML-DSA-44", fixtures=lambda unused: fixtures,
        )

        def observations(unused_transport, cases, *unused):
            for index, case in enumerate(cases):
                status = 406 if case.attack and case.kind != attack.REPLAY else 201
                if reject_baseline and not case.attack:
                    status = 406
                observation = attack.Observation(
                    status, None, {"message": "test response"}, None, 1.25
                )
                state = (Counter({attack.tx_key(case.tx): 1}), Counter())
                yield case, 5001, observation, state, state, [], "2026-11-07T00:00:00Z"
                if interrupt and index == 0:
                    raise KeyboardInterrupt()

        def confirmed(unused_transport, port, normal_cases, *unused):
            return Counter(attack.tx_key(case.tx) for case in normal_cases), Counter()

        def draw(path, samples):
            Path(path).write_bytes(figure_bytes)

        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in {
                "locate_project": lambda root: (root, root / "client.py"),
                "AutoTransport": lambda args: transport,
                "ProjectClient": lambda *args: client,
                "ledger_snapshot": lambda *args: (Counter(), Counter()),
                "mixed_phase_results": observations,
                "replay_phase_results": observations,
                "confirm_in_blocks": confirmed,
                "write_bit_chart": draw,
                "write_mutation_chart": draw,
                "write_replay_chart": draw,
            }.items():
                stack.enter_context(patch.object(attack, name, value))
            stack.enter_context(contextlib.redirect_stdout(output))
            result = attack.run(self.args)
        return result, output.getvalue()

    def assert_previous_outputs(self):
        for path in self.outputs:
            with self.subTest(path=path.name):
                self.assertEqual(path.read_bytes(), b"previous complete output")

    def test_interrupted_run_preserves_complete_outputs(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_attack(interrupt=True)
        self.assert_previous_outputs()

    def test_not_pass_run_preserves_complete_outputs(self):
        result, output = self.run_attack(reject_baseline=True)
        self.assertEqual(result, 1)
        self.assertIn("[RESULT] NOT PASS | thuật toán=ML-DSA-44", output)
        self.assert_previous_outputs()

    def test_successful_same_name_rerun_replaces_complete_output_set(self):
        for figure_bytes in (b"first complete figure", b"second complete figure"):
            with self.subTest(figure_bytes=figure_bytes):
                result, output = self.run_attack(figure_bytes=figure_bytes)
                self.assertEqual(result, 0)
                rows = [json.loads(line) for line in self.log.read_text(
                    encoding="utf-8").splitlines()]
                self.assertEqual(len(rows), 1450)
                self.assertEqual([row["request"] for row in rows], list(range(1, 1451)))
                statuses = Counter((row["scenario"], row["group"], row["http_status"])
                                   for row in rows)
                self.assertEqual(statuses, Counter({
                    (self.attack.BIT, "attack", 406): 300,
                    (self.attack.BIT, "normal", 201): 300,
                    (self.attack.MUTATION, "attack", 406): 300,
                    (self.attack.MUTATION, "normal", 201): 300,
                    (self.attack.REPLAY, "attack", 201): 200,
                    (self.attack.REPLAY, "normal", 201): 50,
                }))
                summary = json.loads(self.log.with_suffix(".summary.json").read_text(
                    encoding="utf-8"))
                self.assertTrue(summary["passed"])
                self.assertEqual(summary["observed_requests"], 1450)
                terminal = self.log.with_suffix(".terminal.log").read_text(encoding="utf-8")
                self.assertEqual(terminal, output.split("[CHART]", 1)[0])
                self.assertTrue(terminal.startswith(
                    "[SIGNER] ML-DSA-44 | miner=5001 | tổng 1450 yêu cầu\n"))
                self.assertIn("HTTP=406 BỊ CHẶN", terminal)
                self.assertIn("latency=1.25ms transaction_rejected", terminal)
                self.assertIn("[RESULT] PASS | thuật toán=ML-DSA-44", terminal)
                for suffix in (".bits.png", ".mutation.png", ".replay.png"):
                    self.assertEqual(self.log.with_suffix(suffix).read_bytes(), figure_bytes)


class RunnerOutputTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.args = types.SimpleNamespace(
            project=["ECDSA"], dry_run=False, keep_raw_logs=True,
        )
        self.old_outputs = [self.root / "old.log", self.root / "old.json",
                            self.root / "sec03_batch_old.json"]
        self.old_outputs += [self.root / name for name in CHART_NAMES]
        for path in self.old_outputs:
            path.write_bytes(b"previous complete output")

    def assert_previous_outputs(self):
        for path in self.old_outputs:
            self.assertEqual(path.read_bytes(), b"previous complete output")

    def test_main_preserves_prior_outputs_on_startup_failure_and_dry_run(self):
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                self.args.dry_run = dry_run
                with patch.object(runner, "ROOT", self.root), \
                        patch.object(runner, "parse_args", return_value=self.args), \
                        patch.object(runner, "prepare_runtime"), \
                        patch.object(runner, "clean_bytecode_caches"), \
                        patch.object(runner, "run_project", side_effect=RuntimeError("startup failed")), \
                        patch.object(runner, "report_batch", return_value=False), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(runner.main(), 0 if dry_run else 1)
                self.assert_previous_outputs()

    def run_batch(self, fail_algorithm=None):
        node_outputs = []

        def run_project(algorithm, directory, args, run_id, pending_outputs=None):
            project = self.root / directory
            project.mkdir(exist_ok=True)
            final = project / "existing_node.log"
            final.write_bytes(b"old node output")
            temporary = final.with_suffix(".log.tmp")
            temporary.write_bytes(b"new node output")
            pending_outputs.append((temporary, final))
            node_outputs.append(final)
            log = project / f"sec03_{run_id}.jsonl"
            rows = [{"scenario": scenario, "group": "attack", "result": "blocked",
                     "evidence_type": "response", "elapsed_ms": 1.25}
                    for scenario in compare.SCENARIOS]
            log.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            return {"algorithm": algorithm, "log": str(log),
                    "status": "test_failed" if algorithm == fail_algorithm else "passed"}

        with patch.object(runner, "ROOT", self.root), \
                patch.object(compare, "ROOT", self.root), \
                patch.object(runner, "run_project", run_project), fake_plotting(), \
                contextlib.redirect_stdout(io.StringIO()):
            result = runner.run_batch(self.args, ["ML-DSA-44", "ECDSA"])
        return result, node_outputs

    def test_batch_publishes_pending_outputs_only_when_every_project_passes(self):
        for failing in ("ECDSA", None):
            with self.subTest(failing=failing):
                result, node_outputs = self.run_batch(fail_algorithm=failing)
                self.assertEqual(result, 1 if failing else 0)
                for path in node_outputs:
                    self.assertEqual(path.read_bytes(),
                                     b"old node output" if failing else b"new node output")
                batches = [path for path in self.root.glob("sec03_batch_*.json")
                           if path.name != "sec03_batch_old.json"]
                self.assertEqual(len(batches), 0 if failing else 1)
                for name in CHART_NAMES:
                    self.assertEqual((self.root / name).read_bytes(),
                                     b"previous complete output" if failing
                                     else b"new comparison figure")

    def test_partial_figure_write_preserves_all_old_comparison_charts(self):
        results = {"ECDSA": {scenario: {"mean_ms": 1.25}
                           for scenario in compare.SCENARIOS}}
        with patch.object(compare, "ROOT", self.root), fake_plotting(fail_on_save=2), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(compare.save_comparison_chart(results))
        self.assert_previous_outputs()


if __name__ == "__main__":
    unittest.main()
