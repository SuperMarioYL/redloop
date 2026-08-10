"""Tests for redloop v0.3.0 fixes.

Covers the two fixes shipped in v0.3.0:

fix-n-zero-default-ignored
    Both attacker ``invent`` methods resolved the count with
    ``n or self.config.n_attacks``, so an explicit ``n=0`` short-circuited to
    the default (8). Now ``n is None`` is the only trigger for the default;
    an explicit 0 is honored. These tests pin the semantics at the unit
    (Attacker / DeterministicAttacker) and campaign (run_attack_campaign)
    levels so the regression cannot silently return.

fix-llm-fallback-misreports-mode
    ``Attacker.invent`` wrapped the LLM call in ``except Exception: return
    mutate_payloads(...)`` but ``is_llm`` / ``mode`` were hardcoded to
    ``True`` / ``"llm"`` and never updated on fallback — so a failed LLM call
    silently produced deterministic mutations labeled as LLM-invented. Now
    the except branch sets ``self.fell_back = True`` and emits a stderr
    warning; ``mode`` returns ``"deterministic (llm-failed)"`` and
    ``is_llm`` returns ``False`` after a fallback, so the eval report and
    console reflect what actually ran. These tests force a failing LLM call
    via a monkeypatch and assert the honest reporting end-to-end through
    ``run_attack_campaign``.

Runnable with::

    pytest tests/test_v030.py
    python tests/test_v030.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

# Make ``redloop`` importable without an installed package.
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from redloop.attacker import (  # noqa: E402
    Attacker,
    AttackerConfig,
    DeterministicAttacker,
    SEED_PAYLOADS,
    build_attacker,
)
from redloop.harden import run_attack_campaign  # noqa: E402


class TestNZeroHonored(unittest.TestCase):
    """fix-n-zero-default-ignored: an explicit n=0 returns [], not the default 8."""

    def test_deterministic_attacker_n_zero_returns_empty(self):
        att = DeterministicAttacker(AttackerConfig(n_attacks=8))
        self.assertEqual(att.invent(SEED_PAYLOADS, n=0), [])

    def test_deterministic_attacker_n_none_uses_default(self):
        att = DeterministicAttacker(AttackerConfig(n_attacks=4))
        payloads = att.invent(SEED_PAYLOADS, n=None)
        self.assertEqual(len(payloads), 4)

    def test_deterministic_attacker_n_explicit_positive_honored(self):
        att = DeterministicAttacker(AttackerConfig(n_attacks=8))
        payloads = att.invent(SEED_PAYLOADS, n=2)
        self.assertEqual(len(payloads), 2)

    def test_llm_attacker_no_key_n_zero_returns_empty(self):
        # An Attacker with no key short-circuits to the deterministic path
        # BEFORE any LLM call, so n=0 must still be honored there too.
        att = Attacker(AttackerConfig(n_attacks=8))
        self.assertFalse(att.config.has_key())
        self.assertEqual(att.invent(SEED_PAYLOADS, n=0), [])

    def test_llm_attacker_no_key_n_none_uses_default(self):
        att = Attacker(AttackerConfig(n_attacks=3))
        payloads = att.invent(SEED_PAYLOADS, n=None)
        self.assertEqual(len(payloads), 3)

    def test_run_attack_campaign_n_zero_produces_zero_attacks(self):
        attacker = build_attacker(AttackerConfig(n_attacks=8))
        results, pairs, report = run_attack_campaign(attacker=attacker, n=0)
        self.assertEqual(results, [])
        self.assertEqual(pairs, [])
        self.assertEqual(report.total_attacks, 0)
        self.assertEqual(report.landed, 0)


class TestLLMFallbackHonesty(unittest.TestCase):
    """fix-llm-fallback-misreports-mode: a failed LLM call is reported honestly."""

    def test_fresh_llm_attacker_reports_llm_before_any_call(self):
        # No call made yet -> no false positive. mode/is_llm still advertise LLM.
        att = Attacker(AttackerConfig(api_key="sk-test"))
        self.assertTrue(att.is_llm)
        self.assertEqual(att.mode, "llm")
        self.assertFalse(att.fell_back)

    def test_failed_llm_call_sets_fell_back_and_flips_mode(self):
        att = Attacker(AttackerConfig(api_key="sk-test", n_attacks=5))
        # Force the LLM call to raise (bad key / wrong base_url / timeout in prod).
        with mock.patch.object(
            att, "_invent_with_llm", side_effect=RuntimeError("boom: bad base_url")
        ):
            payloads = att.invent(SEED_PAYLOADS, n=5)
        # Fail-soft: still returns deterministic payloads, not an empty list.
        self.assertEqual(len(payloads), 5)
        # Honest reporting:
        self.assertTrue(att.fell_back)
        self.assertFalse(att.is_llm)
        self.assertEqual(att.mode, "deterministic (llm-failed)")

    def test_failed_llm_call_emits_stderr_warning(self):
        att = Attacker(AttackerConfig(api_key="sk-test", n_attacks=3))
        with mock.patch.object(
            att, "_invent_with_llm", side_effect=RuntimeError("connection refused")
        ):
            with mock.patch("sys.stderr") as mock_stderr:
                att.invent(SEED_PAYLOADS, n=3)
                written = "".join(
                    call.args[0] for call in mock_stderr.write.call_args_list
                )
        self.assertIn("attacker LLM call failed", written)
        self.assertIn("connection refused", written)
        self.assertIn("deterministic (llm-failed)", written)

    def test_campaign_report_reads_llm_failed_after_fallback(self):
        # End-to-end: a forced LLM failure makes the eval report read
        # attacker_mode="deterministic (llm-failed)", NOT "llm".
        att = Attacker(AttackerConfig(api_key="sk-test", n_attacks=4))
        with mock.patch.object(
            att, "_invent_with_llm", side_effect=RuntimeError("boom")
        ):
            _results, _pairs, report = run_attack_campaign(attacker=att, n=4)
        self.assertTrue(att.fell_back)
        self.assertEqual(report.attacker_mode, "deterministic (llm-failed)")

    def test_successful_llm_call_does_not_set_fell_back(self):
        # A non-failing LLM path must NOT trip the fallback flag.
        att = Attacker(AttackerConfig(api_key="sk-test", n_attacks=2))
        fake_payloads = SEED_PAYLOADS[:2]

        def _fake_invent(seeds, n):
            return fake_payloads[:n]

        with mock.patch.object(att, "_invent_with_llm", side_effect=_fake_invent):
            att.invent(SEED_PAYLOADS, n=2)
        self.assertFalse(att.fell_back)
        self.assertTrue(att.is_llm)
        self.assertEqual(att.mode, "llm")


if __name__ == "__main__":
    unittest.main(verbosity=2)
