# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
