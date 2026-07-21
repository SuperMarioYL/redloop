"""RedLoop configuration loader.

Reads and writes the ``redloop.toml`` file that configures the attacker LLM
(OpenAI-compatible) and the target agent. The shipped ``redloop.toml`` at the
repo root is a tracked template; ``redloop init`` writes a local copy.

Public surface
--------------
Types:    TargetConfig, RedLoopConfig
Helpers:  load_config, write_default_config, DEFAULT_CONFIG_CONTENT
Consts:   DEFAULT_CONFIG_PATH
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from redloop.attacker import AttackerConfig

__all__ = [
    "TargetConfig",
    "RedLoopConfig",
    "load_config",
    "write_default_config",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_CONFIG_CONTENT",
]

DEFAULT_CONFIG_PATH = "redloop.toml"

DEFAULT_CONFIG_CONTENT = """\
# RedLoop configuration.
# `redloop init` writes this template; `redloop run` reads it.
# Lines starting with # are comments. Uncomment a line to override a default.

# ---- Attacker LLM (OpenAI-compatible) ----
# The attacker auto-invents prompt-injection payloads. Any OpenAI-compatible
# endpoint works: official OpenAI, ollama, vLLM, DashScope, a local proxy.
[attacker]
model = "gpt-4o-mini"          # any OpenAI-compatible chat model
# base_url = "http://localhost:11434/v1"  # ollama / vLLM / proxy. Empty = official OpenAI.
# api_key = ""                  # or set the REDLOOP_ATTACKER_KEY env var
temperature = 1.0              # higher => more diverse attacks
n_attacks = 8                 # payloads to invent per run
max_tokens = 1024             # cap on the LLM response size
timeout = 60.0                # request timeout (seconds)

# ---- Target agent (the thing under attack) ----
# The in-process tool-using agent loop. v0.1 ships a self-contained mock loop;
# a bring-your-own-agent adapter is deferred (see README roadmap).
[target]
# system_prompt = ""           # defaults to the built-in demo prompt when empty
forbidden_tools = ["send_email"]   # tools the agent must never call unprompted
max_steps = 8                      # safety bound on the agent loop

# ---- Output ----
[output]
# emit_path = "hardening.jsonl"  # where HardeningPair JSONL is written
"""


@dataclass
class TargetConfig:
    """Configuration for the in-process target agent.

    Attributes
    ----------
    system_prompt : str
        The target agent's system prompt. Empty string => the built-in demo
        prompt (from :mod:`redloop.target`).
    forbidden_tools : tuple[str, ...]
        Tools the agent must never call unprompted. A call to any of these
        flags a hijack.
    max_steps : int
        Safety bound on the agent loop (prevents infinite re-injection).
    """

    system_prompt: str = ""
    forbidden_tools: tuple[str, ...] = ("send_email",)
    max_steps: int = 8


@dataclass
class RedLoopConfig:
    """Top-level RedLoop config (attacker + target + output)."""

    attacker: AttackerConfig = field(default_factory=AttackerConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    emit_path: Optional[str] = "hardening.jsonl"


def _coerce_forbidden(raw: Any) -> tuple[str, ...]:
    """Coerce a TOML value into a tuple of forbidden-tool names."""

    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, (list, tuple)):
        return tuple(str(x) for x in raw)
    return ("send_email",)


def load_config(path: Union[str, Path] = DEFAULT_CONFIG_PATH) -> RedLoopConfig:
    """Load a ``redloop.toml`` config file.

    If the file does not exist, returns a default config (the keyless preset
    demo works without any config file). Missing keys fall back to their
    defaults, so a partial config is fine.
    """

    p = Path(path)
    if not p.exists():
        return RedLoopConfig()

    with p.open("rb") as f:
        data = tomllib.load(f)

    a = data.get("attacker", {})
    attacker = AttackerConfig(
        base_url=a.get("base_url") or None,
        api_key=a.get("api_key") or None,
        model=a.get("model", AttackerConfig().model),
        temperature=float(a.get("temperature", 1.0)),
        n_attacks=int(a.get("n_attacks", 8)),
        max_tokens=int(a.get("max_tokens", 1024)),
        timeout=float(a.get("timeout", 60.0)),
    )

    t = data.get("target", {})
    target = TargetConfig(
        system_prompt=t.get("system_prompt", ""),
        forbidden_tools=_coerce_forbidden(t.get("forbidden_tools", ["send_email"])),
        max_steps=int(t.get("max_steps", 8)),
    )

    o = data.get("output", {})
    emit_path = o.get("emit_path", "hardening.jsonl") or None

    return RedLoopConfig(
        attacker=attacker,
        target=target,
        emit_path=emit_path,
    )


def write_default_config(
    path: Union[str, Path] = DEFAULT_CONFIG_PATH,
    overwrite: bool = False,
) -> Path:
    """Write the default ``redloop.toml`` template to ``path``.

    Parameters
    ----------
    path : str | Path
        Destination path (default ``redloop.toml`` in the cwd).
    overwrite : bool
        If False (default), refuse to clobber an existing file.

    Returns
    -------
    Path
        The path that was written.
    """

    p = Path(path)
    if p.exists() and not overwrite:
        raise FileExistsError(
            f"{p} already exists. Pass --force to overwrite, or edit it by hand."
        )
    p.write_text(DEFAULT_CONFIG_CONTENT, encoding="utf-8")
    return p


def resolved_attacker_key(config: RedLoopConfig) -> Optional[str]:
    """Resolve the attacker API key from config or the env var."""

    if config.attacker.api_key:
        return config.attacker.api_key
    return os.environ.get("REDLOOP_ATTACKER_KEY")


if __name__ == "__main__":  # pragma: no cover
    cfg = load_config()
    print(f"attacker model: {cfg.attacker.model}")
    print(f"forbidden:      {cfg.target.forbidden_tools}")
    print(f"has key:        {cfg.attacker.has_key()}")
