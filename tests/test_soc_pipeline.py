"""Tests for soc_pipeline.py — stage1_net, stage2_refine, helpers."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

# Allow importing sibling modules when run from any cwd
_SIC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SIC))

import soc_pipeline  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: minimal fake detect_system_profile / build_net / inject_project_data
# ---------------------------------------------------------------------------

FAKE_PROFILE = {"components": ["cf-workers", "token-auth"], "scanners": []}

FAKE_NET = [
    {
        "id": "net-cfworkers-env",
        "tag": "ENV-SECRETS",
        "title": "CF Worker secrets exposure",
        "priority": "p1",
        "description": "Worker secrets in plaintext env.",
        "cwe": "CWE-312",
        "owasp": "A02",
        "mitre": "T1552",
        "probes": ["wrangler secret", "env var leak"],
    },
    {
        "id": "net-token-auth-bypass",
        "tag": "AUTH-BYPASS",
        "title": "Token auth bypass",
        "priority": "p0",
        "description": "Bearer token bypass.",
        "cwe": "CWE-287",
        "owasp": "A07",
        "mitre": "T1078",
        "probes": ["bearer bypass", "jwt none"],
    },
]


# ---------------------------------------------------------------------------
# _slug / _output_dir unit tests
# ---------------------------------------------------------------------------


def test_slug_strips_spaces() -> None:
    assert soc_pipeline._slug("/path/to/my project") == "my project".replace(" ", "-")


def test_slug_returns_directory_name() -> None:
    assert soc_pipeline._slug("C:/Za/sic") == "sic"


def test_output_dir_default(tmp_path: Path) -> None:
    """When base is None, output_dir defaults to sic/_runs/qa/."""
    result = soc_pipeline._output_dir(None, "test-slug")
    # Must be relative to sic package root, ending in _runs/qa
    assert str(result).endswith(str(Path("_runs") / "qa"))


def test_output_dir_custom(tmp_path: Path) -> None:
    """When base is given, output_dir is that base path."""
    result = soc_pipeline._output_dir(str(tmp_path), "test-slug")
    assert result == tmp_path


# ---------------------------------------------------------------------------
# stage1_net
# ---------------------------------------------------------------------------


def _make_template(tmp_path: Path) -> None:
    """Create a minimal template HTML that inject_project_data can read."""
    (tmp_path / "template.html").write_text("<html>{{DATA}}</html>", encoding="utf-8")


def test_stage1_net_writes_html(tmp_path: Path) -> None:
    """stage1_net should produce an HTML file in the output dir."""
    _make_template(tmp_path)
    import sic_to_soc
    import threat_catalog

    with (
        patch.object(
            __import__("project_config"), "detect_system_profile", return_value=FAKE_PROFILE
        ),
        patch.object(threat_catalog, "build_net", return_value=FAKE_NET),
        patch.object(sic_to_soc, "DEFAULT_TEMPLATE", str(tmp_path / "template.html")),
        patch.object(sic_to_soc, "inject_project_data", return_value="<html>injected</html>"),
    ):
        result = soc_pipeline.stage1_net(str(tmp_path), str(tmp_path / "out"))

    assert "output_path" in result
    out = Path(result["output_path"])
    assert out.exists(), f"Expected HTML file at {out}"
    assert out.read_text(encoding="utf-8") == "<html>injected</html>"


def test_stage1_net_returns_net_and_profile(tmp_path: Path) -> None:
    """stage1_net return dict must contain net and profile keys."""
    _make_template(tmp_path)
    import sic_to_soc
    import threat_catalog

    with (
        patch.object(
            __import__("project_config"), "detect_system_profile", return_value=FAKE_PROFILE
        ),
        patch.object(threat_catalog, "build_net", return_value=FAKE_NET),
        patch.object(sic_to_soc, "DEFAULT_TEMPLATE", str(tmp_path / "template.html")),
        patch.object(sic_to_soc, "inject_project_data", return_value="<html></html>"),
    ):
        result = soc_pipeline.stage1_net(str(tmp_path), str(tmp_path / "out"))

    assert result["net"] == FAKE_NET
    assert result["profile"] == FAKE_PROFILE
    assert "slug" in result


def test_stage1_net_empty_net_does_not_crash(tmp_path: Path) -> None:
    """stage1_net with empty net (no components matched) must not raise."""
    _make_template(tmp_path)
    import sic_to_soc
    import threat_catalog

    with (
        patch.object(
            __import__("project_config"),
            "detect_system_profile",
            return_value={"components": [], "scanners": []},
        ),
        patch.object(threat_catalog, "build_net", return_value=[]),
        patch.object(sic_to_soc, "DEFAULT_TEMPLATE", str(tmp_path / "template.html")),
        patch.object(sic_to_soc, "inject_project_data", return_value="<html></html>"),
    ):
        result = soc_pipeline.stage1_net(str(tmp_path), str(tmp_path / "out"))

    assert result["net"] == []


# ---------------------------------------------------------------------------
# stage2_refine with pre-built scan JSON
# ---------------------------------------------------------------------------


def test_stage2_refine_with_scan_json(tmp_path: Path) -> None:
    """stage2_refine should load existing scan JSON and return output_path."""
    _make_template(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps({"findings": []}), encoding="utf-8")

    fake_project_data = {
        "netControls": [
            {"id": "net-cfworkers-env", "status": "proven"},
            {"id": "net-token-auth-bypass", "status": "untested"},
        ]
    }

    import sic_to_soc
    import threat_catalog

    with (
        patch.object(
            __import__("project_config"), "detect_system_profile", return_value=FAKE_PROFILE
        ),
        patch.object(threat_catalog, "build_net", return_value=FAKE_NET),
        patch.object(sic_to_soc, "DEFAULT_TEMPLATE", str(tmp_path / "template.html")),
        patch.object(sic_to_soc, "inject_project_data", return_value="<html>refined</html>"),
        patch.object(sic_to_soc, "_collect", return_value=[]),
        patch.object(sic_to_soc, "build_project_data", return_value=fake_project_data),
    ):
        result = soc_pipeline.stage2_refine(
            str(tmp_path),
            scan_json=str(scan_file),
            output_base=str(tmp_path / "out"),
        )

    assert "output_path" in result
    out = Path(result["output_path"])
    assert out.exists()
    assert result["proven_count"] == 1
    assert result["untested_count"] == 1


def test_stage2_refine_counts_zero_when_no_net_controls(tmp_path: Path) -> None:
    """stage2_refine proven/untested counts are 0 when netControls is absent."""
    _make_template(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps({"findings": []}), encoding="utf-8")

    import sic_to_soc
    import threat_catalog

    with (
        patch.object(
            __import__("project_config"), "detect_system_profile", return_value=FAKE_PROFILE
        ),
        patch.object(threat_catalog, "build_net", return_value=FAKE_NET),
        patch.object(sic_to_soc, "DEFAULT_TEMPLATE", str(tmp_path / "template.html")),
        patch.object(sic_to_soc, "inject_project_data", return_value="<html></html>"),
        patch.object(sic_to_soc, "_collect", return_value=[]),
        patch.object(sic_to_soc, "build_project_data", return_value={}),
    ):
        result = soc_pipeline.stage2_refine(
            str(tmp_path),
            scan_json=str(scan_file),
            output_base=str(tmp_path / "out"),
        )

    assert result["proven_count"] == 0
    assert result["untested_count"] == 0
