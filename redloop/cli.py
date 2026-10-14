"""RedLoop CLI (typer-based).

Commands
--------
    redloop init            Write a local redloop.toml config template.
    redloop run             Run the self-play red-team loop (auto-invents
                           attacks, replays them, emits hardening JSONL +
                           an eval report). Needs an attacker LLM key for
                           the headline mode; falls back to keyless
                           mutation when no key is set.
    redloop run --preset demo   Keyless demo: replays one hand-crafted
                                injection, prints the hijack.
    redloop run --emit PATH     Write HardeningPair JSONL to PATH.
    redloop probe          Run the keyless demo and print the hijack
                           (alias for `run --preset demo`).

Public surface
--------------
    app : typer.Typer   The CLI entry point (``redloop = "redloop.cli:app"``).
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from redloop import __version__
from redloop.attacker import AttackerConfig, SEED_PAYLOADS, build_attacker
from redloop.config import (
    DEFAULT_CONFIG_PATH,
    RedLoopConfig,
    load_config,
    write_default_config,
)
from redloop.harden import run_attack_campaign
from redloop.presets.demo import DEMO_PRESET_NAME, print_demo_result, run_preset_demo

__all__ = ["app"]

app = typer.Typer(
    name="redloop",
    help=(
        "Open-source adversarial prompt-injection red-team generator. "
        "Auto-invents tool-call-hijacking attacks against your Coding Agent "
        "and emits hardening training data."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()


def _user_error(message: str) -> None:
    """Print ONE named user-input error and exit 2 (v0.6.0 error boundary).

    User-input failures (a malformed redloop.toml, an unwritable --emit path)
    must surface as a single actionable line, not typer's raw internal
    traceback (v0.6.0 fix-cli-input-error-tracebacks: a typo'd config file used
    to leak ~40 frames of tomllib internals). The message is escaped so OSError
    strings like "[Errno 21] ..." are not parsed as rich markup.
    """
    console.print(f"[red]{escape(message)}[/red]")
    raise typer.Exit(2)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"redloop {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the RedLoop version and exit.",
    ),
) -> None:
    """RedLoop - adversarial prompt-injection red-team generator."""


@app.command()
def init(
    path: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--path",
        "-o",
        help="Where to write the config file.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite an existing config file.",
    ),
) -> None:
    """Write a local redloop.toml config template.

    Edit the generated file to point the attacker at an OpenAI-compatible
    endpoint (official OpenAI, ollama, vLLM, DashScope, a local proxy).
    """

    try:
        written = write_default_config(path, overwrite=force)
    except FileExistsError as exc:
        console.print(
            Panel(
                Text.assemble(
                    (f"{path} already exists.\n", "yellow"),
                    ("Pass --force to overwrite, or edit it by hand.", "dim"),
                ),
                title="[yellow]redloop init[/yellow]",
                border_style="yellow",
            )
        )
        raise typer.Exit(1) from exc

    console.print(
        Panel(
            Text.assemble(
                ("Config written to ", "green"),
                (str(written), "bold green"),
                ("\n\nEdit it to set the attacker model + endpoint, then:\n", "white"),
                ("  redloop run --preset demo   # keyless, no key needed\n", "cyan"),
                ("  redloop run                  # auto-invent (needs a key)\n", "cyan"),
            ),
            title="[bold green]redloop init[/bold green]",
            border_style="green",
        )
    )


@app.command()
def run(
    preset: Optional[str] = typer.Option(
        None,
        "--preset",
        "-p",
        help=f"Preset scenario to run (currently only '{DEMO_PRESET_NAME}').",
    ),
    emit: Optional[Path] = typer.Option(
        None,
        "--emit",
        "-e",
        help="Write HardeningPair JSONL to this path (default: hardening.jsonl).",
    ),
    n: Optional[int] = typer.Option(
        None,
        "--n",
        "-n",
        help="Number of attacks to invent (default: from config, 8).",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="Override the attacker model id.",
    ),
    config_path: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        "-c",
        help="Path to the redloop.toml config file.",
    ),
    no_emit: bool = typer.Option(
        False,
        "--no-emit",
        help="Do not write a hardening.jsonl file (print the eval report only).",
    ),
) -> None:
    """Run the self-play red-team loop.

    Without --preset, the attacker auto-invents N prompt-injection payloads,
    replays each against the in-process target agent, and for every
    successful hijack emits a HardeningPair (attack + desired-safe-response +
    exploit trace) as JSONL, plus a terminal eval report.

    The keyless preset demo (--preset demo) replays one hand-crafted
    injection and prints the hijack - no API key needed.
    """

    if preset is not None and preset != DEMO_PRESET_NAME:
        console.print(
            f"[red]Unknown preset '{preset}'. Available: {DEMO_PRESET_NAME}[/red]"
        )
        raise typer.Exit(2)

    if preset == DEMO_PRESET_NAME:
        emit_path = None if no_emit else (emit or "demo_hardening.jsonl")
        # v0.6.0 (fix-cli-input-error-tracebacks): the demo's only filesystem
        # I/O is the emit write — an unwritable path must print one named
        # error + exit 2, not a raw traceback from emit_jsonl's mkdir.
        try:
            result = run_preset_demo(emit_path=emit_path)
        except OSError as exc:
            _user_error(f"Cannot write {emit_path}: {exc}")
        print_demo_result(result, emit_path=emit_path)
        if not result.hijacked:
            raise typer.Exit(1)
        return

    # Full auto-invention mode.
    # v0.6.0 (fix-cli-input-error-tracebacks): the config file is hand-edited
    # by design, so malformed TOML, a bad value type (int()/float() coercion),
    # and an unreadable --config path are the most likely user errors — print
    # one named error + exit 2 instead of leaking the internal traceback.
    try:
        config = load_config(config_path)
    except (tomllib.TOMLDecodeError, ValueError, TypeError, OSError) as exc:
        _user_error(f"Invalid config file {config_path}: {exc}")

    attacker_cfg = config.attacker
    if model is not None:
        attacker_cfg = AttackerConfig(
            base_url=attacker_cfg.base_url,
            api_key=attacker_cfg.api_key,
            model=model,
            temperature=attacker_cfg.temperature,
            n_attacks=attacker_cfg.n_attacks,
            max_tokens=attacker_cfg.max_tokens,
            timeout=attacker_cfg.timeout,
        )

    emit_path: Optional[Path]
    if no_emit:
        emit_path = None
    else:
        emit_path = emit or Path(config.emit_path or "hardening.jsonl")

    attacker = build_attacker(attacker_cfg)

    mode_label = "LLM" if attacker.is_llm else "keyless (deterministic)"
    if not attacker.is_llm:
        console.print(
            Panel(
                Text.assemble(
                    ("No attacker API key set (REDLOOP_ATTACKER_KEY or redloop.toml).\n", "yellow"),
                    (
                        "Falling back to keyless deterministic mutation. The self-play "
                        "loop still closes; set a key to enable LLM-driven attack invention.\n",
                        "dim",
                    ),
                    (f"Attacker mode: {mode_label}", "cyan"),
                ),
                title="[yellow]keyless fallback[/yellow]",
                border_style="yellow",
            )
        )
    else:
        console.print(
            f"[cyan]Attacker mode: {mode_label}  model: {attacker_cfg.model}[/cyan]"
        )

    # v0.6.0 (fix-cli-input-error-tracebacks): the campaign's only filesystem
    # I/O is the emit write — an unwritable --emit path must print one named
    # error + exit 2, not a raw traceback from emit_jsonl's mkdir.
    try:
        results, pairs, report = run_attack_campaign(
            attacker=attacker,
            seeds=SEED_PAYLOADS,
            n=n,
            emit_path=emit_path,
            forbidden_tools=config.target.forbidden_tools,
            max_steps=config.target.max_steps,
            system_prompt=config.target.system_prompt or None,
        )
    except OSError as exc:
        _user_error(f"Cannot write {emit_path}: {exc}")

    # v0.3.0 (fix-llm-fallback-misreports-mode): if the LLM attacker raised
    # and fell back to deterministic mutation, surface it as a yellow panel so
    # the console reflects what actually ran (the eval report already reads
    # attacker_mode="deterministic (llm-failed)" via Attacker.mode).
    if getattr(attacker, "fell_back", False):
        console.print(
            Panel(
                Text.assemble(
                    ("The attacker LLM call FAILED; ran deterministic mutations instead.\n", "yellow"),
                    (f"Attacker mode: {attacker.mode}\n", "cyan"),
                    (
                        "The emitted JSONL is deterministic, NOT LLM-invented — "
                        "the headline feature did not run. Fix the attacker key/endpoint "
                        "and re-run for LLM-invented attacks.",
                        "dim",
                    ),
                ),
                title="[yellow]llm-failed fallback[/yellow]",
                border_style="yellow",
            )
        )

    from redloop.harden import print_eval_report

    print_eval_report(report)

    if emit_path and pairs:
        console.print(
            f"\n[green]Wrote {len(pairs)} hardening pair(s) to {emit_path}[/green]"
        )
    elif emit_path and not pairs:
        console.print("\n[yellow]No hijacks landed; no hardening pairs emitted.[/yellow]")


@app.command()
def probe(
    emit: Optional[Path] = typer.Option(
        None,
        "--emit",
        "-e",
        help="Write the demo HardeningPair JSONL to this path (default: dry-run, no file).",
    ),
    no_emit: bool = typer.Option(
        False,
        "--no-emit",
        help="Explicitly suppress the JSONL write (the default dry-run behavior).",
    ),
) -> None:
    """Quick alias for `run --preset demo` (keyless hijack demo).

    Defaults to a dry run (no JSONL written) so a quick probe never litters a
    file; pass ``--emit <path>`` to capture the hardening pair, mirroring the
    ``run --preset demo`` flag surface.
    """

    emit_path = None if no_emit else emit
    # v0.6.0 (fix-cli-input-error-tracebacks): same emit-write boundary as
    # `run --preset demo` — one named error + exit 2, no raw traceback.
    try:
        result = run_preset_demo(emit_path=emit_path)
    except OSError as exc:
        _user_error(f"Cannot write {emit_path}: {exc}")
    print_demo_result(result, emit_path=emit_path)
    if not result.hijacked:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
