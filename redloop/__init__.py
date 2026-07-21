"""RedLoop - open-source adversarial prompt-injection red-team generator.

RedLoop auto-invents tool-call-hijacking attacks against a running tool-using
Agent and turns successful exploits into hardening training data (JSONL) -
the open equivalent of OpenAI's internal GPT-Red.

Public API
----------
    Target agent loop .... :mod:`redloop.target`
    Attacker (LLM/keyless): :mod:`redloop.attacker`
    Replay harness ....... :mod:`redloop.replay`
    Hardening emitter .... :mod:`redloop.harden`
    Configuration ........ :mod:`redloop.config`
    Keyless demo preset .. :mod:`redloop.presets.demo`
    CLI .................. :mod:`redloop.cli`
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
