"""Tests for threat_catalog.py — SYSTEM_COMPONENTS, build_net, adjudicate_net."""
from __future__ import annotations

import sys
from pathlib import Path

# Allow importing sibling modules when run from any cwd
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_catalog import SYSTEM_COMPONENTS, _probe_match, adjudicate_net, build_net


def test_system_components_has_thirteen_keys() -> None:
    """SYSTEM_COMPONENTS must contain 13 component entries (12 + app-server)."""
    assert len(SYSTEM_COMPONENTS) == 13, (
        f"Expected 13 components, got {len(SYSTEM_COMPONENTS)}: {list(SYSTEM_COMPONENTS)}"
    )


def test_app_server_component_present() -> None:
    """app-server must be registered with its four threat sections."""
    assert "app-server" in SYSTEM_COMPONENTS
    ids = {s["id"] for s in SYSTEM_COMPONENTS["app-server"]}
    assert ids == {
        "net-appserver-authmw",
        "net-appserver-injection",
        "net-appserver-errorleak",
        "net-appserver-ratelimit",
    }


def test_all_sections_have_required_fields() -> None:
    """Every section in every component must have id, tag, title, priority, probes."""
    required = {"id", "tag", "title", "priority", "probes"}
    for comp_key, sections in SYSTEM_COMPONENTS.items():
        assert isinstance(sections, list), f"{comp_key} sections must be a list"
        for section in sections:
            missing = required - set(section.keys())
            assert not missing, (
                f"Component {comp_key!r} section {section.get('id')!r} missing: {missing}"
            )


def test_build_net_empty_profile() -> None:
    """build_net with no components returns an empty list."""
    profile: dict = {"components": [], "scanners": []}
    net = build_net(profile)
    assert net == []


def test_build_net_single_component() -> None:
    """build_net with one known component returns its sections."""
    profile = {"components": ["cf-workers"], "scanners": []}
    net = build_net(profile)
    # cf-workers is in SYSTEM_COMPONENTS — must return non-empty
    assert len(net) > 0
    ids = [s["id"] for s in net]
    # all returned sections must belong to the cf-workers catalog entry
    valid_ids = {s["id"] for s in SYSTEM_COMPONENTS["cf-workers"]}
    for sid in ids:
        assert sid in valid_ids, f"Section id {sid!r} not in cf-workers catalog"


def test_build_net_priority_order() -> None:
    """build_net must return sections sorted p0 first, then p1, then p2."""
    profile = {"components": list(SYSTEM_COMPONENTS.keys()), "scanners": []}
    net = build_net(profile)
    assert len(net) > 0

    priority_order = {"p0": 0, "p1": 1, "p2": 2}
    priorities = [priority_order.get(s.get("priority", "p2"), 2) for s in net]
    assert priorities == sorted(priorities), (
        "Sections are not sorted by priority (p0 < p1 < p2)"
    )


def test_probe_match_hit() -> None:
    """_probe_match returns True when a finding name/description matches a probe."""
    finding = {"name": "jwt secret exposed in env var", "description": ""}
    probes = ["jwt", "auth bypass", "token leak"]
    assert _probe_match(finding, probes) is True


def test_probe_match_miss() -> None:
    """_probe_match returns False when no probe matches the finding."""
    finding = {"name": "open port 22", "description": "SSH exposed"}
    probes = ["jwt", "sql injection", "cors misconfiguration"]
    assert _probe_match(finding, probes) is False


def test_probe_match_ignores_severity_only_finding() -> None:
    """A finding whose only signal is severity:'high' must match zero net sections.

    Severity is not a topical field — matching against it made every high
    finding bind to every section. _probe_match must ignore it entirely.
    """
    finding = {"severity": "high", "type": "high", "category": "high"}
    matched_any = False
    for sections in SYSTEM_COMPONENTS.values():
        for section in sections:
            if _probe_match(finding, section.get("probes", [])):
                matched_any = True
    assert matched_any is False, "severity-only finding should match no net section"


def test_probe_match_cors_wildcard_hits_cors_section() -> None:
    """A 'CORS wildcard origin' finding matches the cf-workers CORS section."""
    finding = {"name": "CORS wildcard origin", "description": "Access-Control-Allow-Origin: *"}
    cors_section = next(
        s for s in SYSTEM_COMPONENTS["cf-workers"] if s["id"] == "net-cfworkers-cors"
    )
    assert _probe_match(finding, cors_section["probes"]) is True


def test_probe_match_whole_word_not_substring() -> None:
    """Token-boundary matching: a probe must not match inside a larger word."""
    # 'ws' probe should NOT match 'awsome' (substring) but SHOULD match 'ws' token
    finding = {"name": "awsome feature", "description": ""}
    assert _probe_match(finding, ["ws"]) is False


def test_adjudicate_net_refuted_when_scanner_ran_clean() -> None:
    """A covered section with no findings is refuted when its scanner ran."""
    section = dict(
        next(s for s in SYSTEM_COMPONENTS["secrets-store"]
             if s["id"] == "net-secrets-hardcoded")
    )
    net = [section]
    result = adjudicate_net(net, findings=[], scanners_run=["trivy"])
    assert result[0]["status"] == "refuted", (
        "covered section + scanner ran + no findings should be refuted"
    )


def test_adjudicate_net_untested_when_scanner_absent() -> None:
    """A covered section with no findings is untested when its scanner did NOT run."""
    section = dict(
        next(s for s in SYSTEM_COMPONENTS["secrets-store"]
             if s["id"] == "net-secrets-hardcoded")
    )
    net = [section]
    result = adjudicate_net(net, findings=[], scanners_run=["nuclei"])
    assert result[0]["status"] == "untested"


def test_adjudicate_net_marks_proven_and_untested() -> None:
    """adjudicate_net correctly marks sections as proven/untested."""
    # Craft a minimal net using first section of cf-workers
    net = [
        dict(SYSTEM_COMPONENTS["cf-workers"][0]),  # copy first section
        dict(SYSTEM_COMPONENTS["sql"][0]),
    ]
    # Finding that matches a probe in cf-workers[0] but not sql-d1[0]
    cf_probe = net[0]["probes"][0]  # grab first probe string
    findings = [{"name": cf_probe, "description": ""}]

    result = adjudicate_net(net, findings)
    assert len(result) == 2

    statuses = {s["id"]: s["status"] for s in result}
    # The cf-workers section should be proven; sql-d1 section should be untested
    cf_id = net[0]["id"]
    sql_id = net[1]["id"]
    assert statuses[cf_id] == "proven", f"Expected proven for {cf_id}, got {statuses[cf_id]}"
    assert statuses[sql_id] == "untested", (
        f"Expected untested for {sql_id}, got {statuses[sql_id]}"
    )
