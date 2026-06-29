"""Tests for llm_corpus_detector.py."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_corpus_detector import CorpusDetector

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "data" / "system-prompts-corpus" / "manifest.json"


def test_manifest_loads() -> None:
    detector = CorpusDetector(MANIFEST_PATH)
    assert len(detector.signatures) >= 200


def test_score_exact_match() -> None:
    detector = CorpusDetector(MANIFEST_PATH)
    # Use the preview text of the first entry — should score high
    preview = detector.signatures[0].get("preview", "")
    if not preview:
        return  # skip if no preview
    score, entry = detector.score(preview)
    assert score > 0.8, f"Expected score > 0.8 for exact preview match, got {score}"
    assert entry is not None


def test_score_no_match() -> None:
    detector = CorpusDetector(MANIFEST_PATH)
    # Random unrelated text should score near zero
    text = "xyzzy frobozz quux garply waldo corge grault"
    score, _ = detector.score(text)
    assert score < 0.1, f"Expected score < 0.1 for unrelated text, got {score}"


def test_detect_returns_none_below_threshold() -> None:
    detector = CorpusDetector(MANIFEST_PATH)
    result = detector.detect("xyzzy frobozz quux garply waldo corge grault", threshold=0.35)
    assert result is None


def test_detect_returns_finding_above_threshold() -> None:
    detector = CorpusDetector(MANIFEST_PATH)
    preview = detector.signatures[0].get("preview", "")
    if not preview:
        return
    result = detector.detect(preview, threshold=0.35)
    assert result is not None
    assert "score" in result
    assert "match" in result
    assert result["finding"] == "system-prompt-leak"
