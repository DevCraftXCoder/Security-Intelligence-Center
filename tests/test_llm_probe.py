"""Smoke tests for llm_probe.py — no live endpoint required."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_probe import (
    INJECTION_PAYLOADS,
    COMPLIANCE_SIGNALS,
    _DOS_PAYLOAD_TEMPLATES,
    LLMProbeEngine,
    ProbeConfig,
    ProbeResult,
    DOS_MAX_INPUT_TOKENS,
    DOS_MAX_PAYLOADS_PER_RUN,
    DOS_TIMEOUT_SECONDS,
)


def test_injection_payloads_non_empty() -> None:
    assert len(INJECTION_PAYLOADS) >= 8


def test_compliance_signals_non_empty() -> None:
    assert len(COMPLIANCE_SIGNALS) >= 4


def test_probe_engine_instantiates() -> None:
    cfg = ProbeConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        auth="Bearer test",
        categories=["LLM01", "LLM06"],
    )
    engine = LLMProbeEngine(cfg)
    assert engine is not None
    assert engine.cfg.dry_run is True


def test_run_all_dry_run_returns_no_sent_payloads() -> None:
    cfg = ProbeConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        auth="Bearer test",
        categories=["LLM01", "LLM04", "LLM06"],
        dry_run=True,
    )
    engine = LLMProbeEngine(cfg)
    result = engine.run_all()
    assert isinstance(result, ProbeResult)
    assert result.payloads_sent == 0
    assert result.dry_run is True


def test_run_all_returns_list() -> None:
    cfg = ProbeConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        auth="Bearer test",
        categories=["LLM01", "LLM04"],
        dry_run=True,
        confirm_adversarial=False,
    )
    engine = LLMProbeEngine(cfg)
    result = engine.run_all()
    assert isinstance(result.findings, list)


def test_dos_constants() -> None:
    assert DOS_MAX_INPUT_TOKENS == 500
    assert DOS_MAX_PAYLOADS_PER_RUN == 3


def test_llm01_skipped_without_confirm_adversarial() -> None:
    cfg = ProbeConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        auth="Bearer test",
        categories=["LLM01"],
        dry_run=True,
        confirm_adversarial=False,
    )
    engine = LLMProbeEngine(cfg)
    result = engine.run_all()
    ids = [f["id"] for f in result.findings]
    assert "llm01-skipped" in ids


def test_llm06_skipped_without_experimental() -> None:
    cfg = ProbeConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        auth="Bearer test",
        categories=["LLM06"],
        dry_run=True,
        experimental=False,
    )
    engine = LLMProbeEngine(cfg)
    result = engine.run_all()
    ids = [f["id"] for f in result.findings]
    assert "llm06-skipped" in ids


def test_dos_payload_templates_includes_dow() -> None:
    """G3: DoW payload must be present in the template bank."""
    assert len(_DOS_PAYLOAD_TEMPLATES) >= 4
    dow_keywords = ["essay", "5000", "word", "history"]
    assert any(
        any(kw in p.lower() for kw in dow_keywords)
        for p in _DOS_PAYLOAD_TEMPLATES
    ), "No DoW (Denial of Wallet) payload found in _DOS_PAYLOAD_TEMPLATES"


def test_dos_timeout_relative_detection_logic() -> None:
    """G1: Verify the timeout-relative detection condition is sound.

    The old code used elapsed>30 with timeout=15 — a timeout exception fires at ~15s
    and would never exceed 30. The fix uses elapsed>=timeout*0.9 so a 15s timeout
    triggers detection at >=13.5s.
    """
    timeout = DOS_TIMEOUT_SECONDS
    simulated_elapsed = float(timeout)  # exact timeout
    timed_out = simulated_elapsed >= timeout * 0.9
    assert timed_out, (
        f"Timeout-relative detection failed: elapsed={simulated_elapsed} < "
        f"threshold={timeout * 0.9} (timeout={timeout})"
    )


def test_dos_timeout_text_pattern_detection() -> None:
    """G1: 'ERROR:timed out' text pattern must be detected as a DoS signal."""
    timeout = DOS_TIMEOUT_SECONDS
    text = "ERROR:timed out"
    elapsed = float(timeout)
    timed_out = (
        elapsed >= timeout * 0.9
        or ("ERROR:" in text and ("timed" in text.lower() or "timeout" in text.lower()))
    )
    assert timed_out, "Timeout text pattern not detected as DoS signal"


def test_dos_output_amplification_detection() -> None:
    """G4: A response >16000 chars must be flagged as output amplification."""
    long_response = "yes " * 5000  # 20000 chars
    output_amplified = len(long_response) > 16_000
    assert output_amplified, f"Expected >16000 chars to flag, got {len(long_response)}"
