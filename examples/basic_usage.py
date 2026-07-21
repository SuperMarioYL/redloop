"""Example: programmatic use of the RedLoop API.

Run with::

    python examples/basic_usage.py

This script demonstrates the three milestones end-to-end, keyless (no API
key required):

1. Build the target agent and replay the hand-crafted demo injection.
2. Auto-invent novel attacks via the keyless deterministic mutator.
3. Convert every successful exploit into a HardeningPair and emit JSONL.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from redloop.attacker import AttackerConfig, build_attacker
from redloop.harden import run_attack_campaign
from redloop.presets.demo import run_preset_demo, print_demo_result


def main() -> None:
    # 1. Keyless preset demo: one hand-crafted injection, visibly hijacks.
    print("=" * 60)
    print("1. Preset demo (keyless)")
    print("=" * 60)
    result = run_preset_demo()
    print_demo_result(result)

    # 2. Full campaign: auto-invent -> replay -> harden -> emit.
    print("\n" + "=" * 60)
    print("2. Full attack campaign (keyless deterministic attacker)")
    print("=" * 60)
    attacker = build_attacker(AttackerConfig(n_attacks=5))
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "hardening.jsonl"
        results, pairs, report = run_attack_campaign(
            attacker=attacker, emit_path=out, n=5,
        )
        print(f"Invented {len(results)} attacks, {len(pairs)} landed.")
        print(f"Hardening pairs written to: {out}")
        print(f"Sample pair (first 200 chars):\n{out.read_text()[:200]}...")


if __name__ == "__main__":
    main()
