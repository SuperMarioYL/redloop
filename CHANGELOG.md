# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-28

### Fixed
- **Stop mislabeling an empty / content-filtered attacker-LLM response as
  `llm`** (`fix-llm-empty-content-mislabeled-llm`). `Attacker._invent_with_llm`
  returned `parse_llm_payloads(text, n, seeds)`, and when the LLM returned
  empty/`None` content (a content-filtered response, a `finish_reason=length`
  cut, or prose with no `send_email(...)` directive) `parse_llm_payloads`
  padded to deterministic mutations WITHOUT raising — so `fell_back` stayed
  `False`, `Attacker.mode` returned `"llm"`, and the eval report read
  `attacker_mode="llm"` while the emitted payloads were deterministic. This is
  the same honesty bug v0.3.0's `fix-llm-fallback-misreports-mode` killed, but
  that fix closed only the exception-raising path; the empty-content path
  (the realistic trigger for an adversarial prompt generator) was left open.
  `parse_llm_payloads` now takes a `pad` flag; `_invent_with_llm` parses with
  `pad=False`, and a zero-real-payload response raises into the existing
  honest except-branch (`fell_back=True`, mode
  `"deterministic (llm-failed)"`). A partial response still pads to `n` and
  honestly reports `"llm"`.
- **Stop false-negativing the tool's own exfil attacks down to ESCAPE**
  (`fix-severity-misses-own-exfil-attacks`). `classify_severity`'s keyword
  lists omitted the mutator's own exfil vocabulary, so a `send_email`
  exfiltrating `private keys` to `collect@malware.xyz` / `leak@dark.io` was
  classified `ESCAPE` instead of `DATA_EXFIL`, understating the eval report's
  severity. The body markers now include `"private key"` and the recipient
  markers now include `"malware"`, `"dark"`, `"leak"`, `"collect"` (covering
  the attack surface RedLoop itself generates; `"drop"` is intentionally
  omitted to avoid false-positive on benign `dropbox@...` addresses — the
  mutator's `drop@exfil.tld` is already caught by `"exfil"`).
- **Stop leaving a stale `hardening.jsonl` on a no-land run**
  (`fix-stale-hardening-jsonl-on-no-land`). `run_attack_campaign` gated emit
  on `if emit_path is not None and pairs`, so a run that landed zero hijacks
  (a hardened agent, a weak attacker, an `--n 0` sweep) never opened the file
  and a prior run's pairs persisted on disk, mislabeled as this run's output
  — a stale-data hazard for a security tool whose JSONL feeds training. Now
  the file is always written when an `emit_path` is requested; a no-land run
  produces an empty file (correctly reflecting "zero pairs this run").

### Added
- `tests/test_v040.py` — regression coverage for all three fixes: empty/None/
  no-directive LLM content trips the honest fallback (and a partial response
  does not); the expanded severity markers catch the mutator's own exfil
  attacks without false-positiving a benign `dropbox@...` send; and a no-land
  run with `--emit` truncates a prior run's `hardening.jsonl` to zero lines.

## [0.3.0] - 2026-08-11

### Fixed
- **Stop misreporting `attacker_mode` as `"llm"` when the LLM call failed and
  fell back to deterministic** (`fix-llm-fallback-misreports-mode`). `Attacker.invent`
  wrapped the LLM call in `except Exception: return mutate_payloads(...)` but
  `Attacker.is_llm` / `Attacker.mode` were hardcoded to `True` / `"llm"` and never
  updated on fallback — so a bad/expired key, wrong `base_url`, timeout, or empty
  choices silently produced deterministic mutations labeled as LLM-invented, with no
  warning. For a security red-team tool whose JSONL feeds hardening/training data, the
  output was weaker than the user believed. Now the except branch sets a `fell_back`
  flag and emits a stderr warning; `Attacker.mode` returns
  `"deterministic (llm-failed)"` and `is_llm` returns `False` after a fallback, so the
  eval report (`run_attack_campaign` → `build_eval_report`) and the CLI's post-campaign
  yellow panel both reflect what actually ran. The fail-soft return is preserved.
- **Honor an explicit `--n 0` instead of treating it as "use the default"**
  (`fix-n-zero-default-ignored`). Both attacker `invent` methods resolved the count with
  `n or self.config.n_attacks`, so `0 or 8` evaluated to `8` — `redloop run --n 0` and
  programmatic `run_attack_campaign(..., n=0)` ran 8 attacks instead of 0. Replaced
  with `self.config.n_attacks if n is None else n` in both `Attacker.invent` and
  `DeterministicAttacker.invent` so an explicit 0 is honored (and
  `mutate_payloads(seeds, 0)` already returns `[]` cleanly).

### Added
- `tests/test_v030.py` — regression coverage for both fixes (n=0 honored for both
  attacker classes + `run_attack_campaign`; LLM-fallback sets `fell_back`, flips
  `mode`/`is_llm`, and the campaign report reads `attacker_mode="deterministic
  (llm-failed)"` via a monkeypatched failing LLM call).

## [0.2.0] - 2026-08-03

### Fixed
- Wire the configured `target.system_prompt` through the `redloop run` path
  (`m4_fix_target_system_prompt_unwired`). Previously
  `TargetConfig.system_prompt` (and the `redloop.toml` `[target]` template) was
  advertised but silently ignored — `run_attack_campaign` → `replay_payload` →
  `build_demo_target` hardcoded the demo prompt, so a user could not point
  RedLoop at their own agent's system prompt. `system_prompt` now threads
  end-to-end (empty / `None` falls back to the built-in `DEMO_SYSTEM_PROMPT`,
  preserving the keyless demo). This closes the tool's "attacks against YOUR
  Coding Agent" value prop.
- Give the `probe` command the `--emit` / `--no-emit` flags it advertises as a
  `run --preset demo` alias (`m5_fix_probe_missing_emit_flags`). `probe`
  previously hardcoded `demo_hardening.jsonl` and accepted no emit flags; it
  now defaults to a dry run (no JSONL written) and honors `--emit <path>` to
  capture the hardening pair, mirroring the `run --preset demo` flag surface.

### Added
- `tests/test_v020.py` — regression coverage for both fixes (system_prompt
  wiring at the `build_demo_target` / `replay_payload` / `replay_many` /
  `run_attack_campaign` levels; `probe` dry-run + `--emit` via typer's
  `CliRunner`).

## [0.1.0] - 2026-07-21

### Added
- In-process target agent loop with mock tools (`read_file`, `send_email`) and a
  system prompt that a hand-crafted prompt-injection can hijack into calling
  `send_email`; the harness captures the caught tool call (m1:
  `m1_build_target_loop`).
- Attacker LLM that auto-invents prompt-injection payloads against the target
  loop using a mutation strategy over seed prompts, replays them, and flags
  successful hijacks (m2: `m2_auto_invent_attacks`).
- `HardeningPair` JSONL emission from every successful exploit plus a `rich`
  terminal eval report with severity and landed-attack counts (m3:
  `m3_emit_hardening_data`).
- Keyless preset demo (`redloop run --preset demo`) that replays one
  hand-crafted injection end-to-end without an API key.
- `redloop init` command that writes `redloop.toml` for attacker-model and
  target-agent configuration.
- `redloop run` command that drives the attacker-LLM self-play loop, writes
  `hardening.jsonl`, and prints the eval report.
