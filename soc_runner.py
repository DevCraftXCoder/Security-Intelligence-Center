"""
soc_runner.py — Project-aware scan orchestrator.

Single entry point to scan a project end-to-end. Loads the project's `.sic.yaml`
(or auto-detected defaults via project_config), works out which scanners apply,
and reports what it would run. Actual scanner execution is out of scope here —
this module only wires discovery + planning and logs intended runs to stderr.

CLI:
    python soc_runner.py --project dropstream
    python soc_runner.py --path C:/Za/drop_stream-main
    python soc_runner.py --describe        # dry run, no execution

stdlib only (imports project_config for config + registry).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

import project_config


def _err(msg: str) -> None:
    """Write a namespaced line to stderr."""
    print(f"[soc_runner] {msg}", file=sys.stderr)


class SOCRunner:
    """Orchestrates project discovery and scan planning."""

    def __init__(
        self,
        project_slug: Optional[str] = None,
        project_path: Optional[str] = None,
    ) -> None:
        """Load project config.

        Resolution order:
          1. project_slug -> look up registry for its path.
          2. project_path -> use directly.
          3. neither -> auto-detect from cwd.
        """
        resolved_path: Optional[str] = project_path

        if project_slug and not resolved_path:
            entry = project_config.get_project(project_slug)
            if entry is None:
                _err(f"slug {project_slug!r} not in registry; falling back to cwd")
            else:
                resolved_path = entry.get("path")

        if not resolved_path:
            resolved_path = str(Path.cwd())

        self.project_path: str = str(Path(resolved_path).resolve())
        self.config: dict[str, Any] = project_config.load_config(self.project_path)
        self.slug: str = project_slug or self.config.get("slug", Path(self.project_path).name)

        # Keep the registry fresh so future --project lookups resolve.
        config_path = self.config.get("_config_path") or str(
            Path(self.project_path) / project_config.CONFIG_FILENAME
        )
        project_config.register_project(self.slug, self.project_path, config_path)

    def discover(self) -> dict[str, Any]:
        """Detect project type, list scan targets. Returns a discovery report."""
        targets = self.config.get("targets", []) or []
        scanners = self.config.get("scanners", []) or []
        return {
            "slug": self.config.get("slug", self.slug),
            "name": self.config.get("name", self.slug),
            "asset_tier": self.config.get("asset_tier", "dev"),
            "project_path": self.project_path,
            "config_source": self.config.get("_source", "auto"),
            "config_path": self.config.get("_config_path"),
            "scanners": scanners,
            "targets": targets,
            "suppression_count": len(self.config.get("suppressions", []) or []),
        }

    def _plan(self) -> list[str]:
        """Build the list of scan operations that would run.

        Filesystem/config scanners run against the project path; nuclei runs
        against each declared URL target.
        """
        report = self.discover()
        scanners = report["scanners"]
        targets = report["targets"]
        ops: list[str] = []

        url_targets = [
            t.get("value")
            for t in targets
            if isinstance(t, dict) and t.get("type") == "url" and t.get("value")
        ]

        for scanner in scanners:
            if scanner == "nuclei":
                if url_targets:
                    for url in url_targets:
                        ops.append(f"{scanner} on {url}")
                else:
                    ops.append(f"{scanner} (no URL targets declared — skipped)")
            else:
                ops.append(f"{scanner} on {self.project_path}")

        return ops

    def describe(self) -> None:
        """Print what would be scanned without running anything (dry run)."""
        report = self.discover()
        print(json.dumps(report, indent=2))

        ops = self._plan()
        if not ops:
            _err("no scanners resolved for this project — nothing to run")
            return
        for op in ops:
            _err(f"Would run: {op}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_runner",
        description="Project-aware SIC scan orchestrator (planning only).",
    )
    parser.add_argument("--project", help="Registered project slug to scan.")
    parser.add_argument("--path", help="Filesystem path to the project to scan.")
    parser.add_argument(
        "--describe",
        action="store_true",
        help="Dry run — print the scan plan without executing anything.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        runner = SOCRunner(project_slug=args.project, project_path=args.path)
    except Exception as exc:
        _err(f"failed to initialize runner: {exc}")
        return 1

    # --describe is the only supported action today; execution is out of scope,
    # so a plain invocation also prints the plan rather than silently doing nothing.
    runner.describe()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
