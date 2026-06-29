"""Smoke tests for llm_probe.py — no live endpoint required."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_probe import (
    INJECTION_PAYLOADS,
    COMPLIANCE_SIGNALS,
    LLMProbeEngine,
    ProbeConfig,
    ProbeResult,
    DOS_MAX_INPUT_TOKENS,
    DOS_MAX_PAYLOADS_PER_RUN,
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
