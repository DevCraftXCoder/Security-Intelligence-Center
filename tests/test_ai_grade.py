"""Smoke tests for ai_grade.py — Phase 3 AI-powered finding grader.

Coverage:
    1. Module imports without error
    2. ai_grade_init_db() runs idempotently
    3. grade_finding_route returns 400 when title is missing
    4. grade_finding_route returns 400 when category is missing
    5. grade_finding_route returns 503 when no API key is configured
    6. grade_finding_route returns graded result when AI call is mocked
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure sic/ root is importable
# ---------------------------------------------------------------------------

_SIC_ROOT = Path(__file__).parent.parent
if str(_SIC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SIC_ROOT))


# ---------------------------------------------------------------------------
# Test 1: module imports without error
# ---------------------------------------------------------------------------


def test_ai_grade_imports() -> None:
    """ai_grade module must import cleanly with no side effects."""
    import importlib
    mod = importlib.import_module("ai_grade")
    assert hasattr(mod, "ai_grade_bp"), "Blueprint attribute missing"
    assert hasattr(mod, "ai_grade_init_db"), "Init function missing"


# ---------------------------------------------------------------------------
# Test 2: DB init is idempotent
# ---------------------------------------------------------------------------


def test_ai_grade_init_db_idempotent(tmp_path: Path) -> None:
    """ai_grade_init_db() must succeed when called twice and not raise."""
    import ai_grade

    # Redirect DB to a temp path to avoid polluting ~/.sic/state.db
    original_path = ai_grade._DB_PATH
    ai_grade._DB_PATH = tmp_path / "test_state.db"
    ai_grade._db_init_done = False
    try:
        ai_grade.ai_grade_init_db()
        ai_grade._db_init_done = False  # force second run
        ai_grade.ai_grade_init_db()
    finally:
        ai_grade._DB_PATH = original_path
        ai_grade._db_init_done = False


# ---------------------------------------------------------------------------
# Flask test client fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def flask_client(tmp_path: Path):
    """Return a Flask test client with ai_grade blueprint mounted."""
    from flask import Flask
    import ai_grade

    app = Flask(__name__)
    app.config["TESTING"] = True

    # Redirect DB to tmp
    ai_grade._DB_PATH = tmp_path / "test_state.db"
    ai_grade._db_init_done = False
    ai_grade.ai_grade_init_db()

    app.register_blueprint(ai_grade.ai_grade_bp)
    with app.test_client() as client:
        yield client

    # Cleanup
    import importlib
    importlib.reload(ai_grade)


# ---------------------------------------------------------------------------
# Test 3: missing title -> 400
# ---------------------------------------------------------------------------


def test_grade_missing_title(flask_client) -> None:
    """POST /api/ai/grade without title must return 400."""
    resp = flask_client.post(
        "/api/ai/grade",
        json={"category": "injection", "description": "some description"},
        environ_base={"HTTP_AUTHORIZATION": ""},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data is not None
    assert "title" in data.get("error", "").lower()


# ---------------------------------------------------------------------------
# Test 4: missing category -> 400
# ---------------------------------------------------------------------------


def test_grade_missing_category(flask_client) -> None:
    """POST /api/ai/grade without category must return 400."""
    resp = flask_client.post(
        "/api/ai/grade",
        json={"title": "SQL Injection", "description": "login form"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert "category" in data.get("error", "").lower()


# ---------------------------------------------------------------------------
# Test 5: no API key -> 503
# ---------------------------------------------------------------------------


def test_grade_no_api_key(flask_client) -> None:
    """POST /api/ai/grade with no API keys configured must return 503."""
    env_patch = {
        "OPENROUTER_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
    }
    with patch.dict(os.environ, env_patch, clear=False):
        # Ensure both are absent
        os.environ.pop("OPENROUTER_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        resp = flask_client.post(
            "/api/ai/grade",
            json={"title": "XSS in search", "category": "xss"},
        )
    assert resp.status_code == 503
    data = resp.get_json()
    assert data is not None
    assert data.get("error") == "AI_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Test 6: successful grade with mocked AI call
# ---------------------------------------------------------------------------


def test_grade_success_mocked(flask_client, tmp_path: Path) -> None:
    """POST /api/ai/grade must return a valid grading result when AI is mocked."""
    import ai_grade

    mock_result = {
        "remediation": "Use parameterized queries to prevent injection.",
        "confidence": 0.92,
        "false_positive_risk": "low",
        "one_line_fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "severity": "high",
    }

    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-mock"}):
        with patch.object(ai_grade, "_call_ai", return_value=mock_result):
            resp = flask_client.post(
                "/api/ai/grade",
                json={
                    "title": "SQL Injection in login",
                    "category": "injection",
                    "description": "User-controlled input passed to SQL query.",
                    "severity": "high",
                },
            )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data is not None
    assert data["severity"] == "high"
    assert data["confidence"] == 0.92
    assert "parameterized" in data["remediation"]
    assert data["false_positive_risk"] == "low"
    assert "one_line_fix" in data
