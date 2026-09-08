[简体中文](./README.md) · [Website](https://redloop.lei6393.com) · [GitHub](https://github.com/SuperMarioYL/redloop)

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/hero-dark.svg">
  <img src="./assets/presentation/hero-light.svg" width="960" alt="Hero diagram">
</picture>

# RedLoop

**Turn a replayed injection into an inspectable training record.**

RedLoop creates attack examples, replays them through a built-in tool loop and exports successful forbidden-call traces with a suggested safe response.

## Why use it

A reusable example needs more than a payload string. Keeping the injection location, observed call and expected safe behavior together gives reviewers the context needed to judge a candidate training record.

- **Keep the full example** — Payload, location, outcome and trace stay together.
- **Reproduce without a key** — The demo and deterministic generator run locally.
- **Inspect the generation mode** — Reports distinguish model generation from deterministic fallback.

## Architecture

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-dark.svg">
  <img src="./assets/presentation/architecture-light.svg" width="960" alt="Architecture diagram">
</picture>

The attacker supplies seeded mutations or optional model-generated payloads. Replay constructs a fresh deterministic target with in-memory tools, records forbidden calls, and the hardening module serializes attack, outcome, safe_response and exploit_trace. Reports aggregate the replay outcomes.

| Component | Responsibility |
| --- | --- |
| `Payload generation` | redloop/attacker.py |
| `Fresh replay` | redloop/replay.py |
| `In-memory target` | redloop/target.py |
| `Training records` | redloop/harden.py |

## Install and quickstart

Use the runtime version declared in the repository manifest. The source installation below makes the included example reproducible.

```bash
git clone https://github.com/SuperMarioYL/redloop.git
cd redloop
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Python 3.12+; replay the complete bundled fixture and read its JSONL record from a temporary directory.

```bash
.venv/bin/python examples/presentation_demo.py
```

## Recorded demo

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/process-dark.svg">
  <img src="./assets/presentation/process-light.svg" width="960" alt="Process diagram">
</picture>

The mock target records read_file then send_email and exports one training record; no email leaves the process.

```text
{
  "target": "deterministic in-memory agent",
  "calls": [
    "read_file",
    "send_email"
  ],
  "hijacked": true,
  "severity": "data_exfil",
  "simulated_mailbox_entries": 1,
  "training_records": 1,
  "record_fields": [
    "attack",
    "exploit_trace",
    "outcome",
    "safe_response"
  ]
}
```

The complete command and output are recorded in [docs/demo-results.json](./docs/demo-results.json). Inputs and reproduction code are included in the repository.

![Existing terminal recording](./assets/demo.gif)

The existing recording is retained for context; the text example above documents the reproducible scenario.

## Usage

Run these commands from the repository root after installation. Replace paths for your own data.

```bash
redloop run --preset demo --emit demo-hardening.jsonl
redloop probe
# Review redloop.toml before a campaign:
redloop run --no-emit --n 4
```

## Configuration

redloop.toml defines attacker model, base_url, temperature, n_attacks, max_tokens and timeout; target defines forbidden_tools, max_steps and optional system_prompt. REDLOOP_ATTACKER_KEY enables online attack generation. Without a key the ordinary run uses deterministic generation; API failure can also fall back, so inspect attacker_mode. --no-emit avoids an output file; --emit selects JSONL, which is overwritten per campaign.

## Integrations and responsibilities

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-dark.svg">
  <img src="./assets/presentation/integrations-light.svg" width="960" alt="Integrations diagram">
</picture>

Choose the input and output route that matches your workflow. The local example below exercises the stated subset.

| Route | Implemented role |
| --- | --- |
| Seed payloads | Deterministic attack variants |
| OpenAI-compatible API | Optional attacker generation |
| Mock tool loop | In-memory files and mailbox |
| HardeningPair JSONL | Trace and suggested safe response |
| TOML | Attacker and target settings |

## Limits and next steps

- The target is a deliberately naive rule-based mock, not a live LLM agent. Its hit rate does not measure security of external agents or models.
- send_email writes to an in-memory mailbox; the demo sends no email or user data. forbidden_tools labels detected calls rather than acting as a runtime blocking policy.
- The exported safe responses are templates for review. No fine-tuning or measured hardening improvement is performed.

Bring-your-own-agent adapters and evaluation against real target deployments remain future work; generated examples need review before downstream training.

## License and contributions

See [LICENSE](./LICENSE). When reporting an issue, include a minimal input, the command, and the observed output.
