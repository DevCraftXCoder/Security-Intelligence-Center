"""
soc_runner.py — Project-aware scan orchestrator.

Single entry point to scan a project end-to-end. Loads the project's `.sic.yaml`
(or auto-detected defaults via project_config), works out which scanners apply,
and either reports what it would run (--describe) or actually runs the scanners
(--scan), merging their JSON outputs into a single unified findings file (--merge).

CLI:
    python soc_runner.py --project dropstream
    python soc_runner.py --path C:/Za/drop_stream-main --describe   # dry run
    python soc_runner.py --path C:/Za/drop_stream-main --scan        # run scanners
    python soc_runner.py --path C:/Za/drop_stream-main --scan --merge

stdlib only (imports project_config for config + registry, scan_merge for merge).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import project_config
import scan_merge
import scan_python

# Per-scanner subprocess timeout, in seconds.
SCANNER_TIMEOUT_S: int = 120

# Default output directory for scan + merge artifacts.
DEFAULT_OUTPUT_DIR: str = str(Path(__file__).resolve().parent / "_runs")


def _err(msg: str) -> None:
    """Write a namespaced line to stderr."""
    print(f"[soc_runner] {msg}", file=sys.stderr)


def _out(msg: str) -> None:
    """Write a namespaced progress line to stdout."""
    print(f"[soc_runner] {msg}")


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

    # ------------------------------------------------------------------
    # Real scanner execution
    # ------------------------------------------------------------------

    def _scanner_commands(self, out_file: str) -> dict[str, list[str]]:
        """Build the argv for a filesystem/config scanner writing to out_file.

        URL-scoped scanners (nuclei) are handled separately in scan() since they
        run once per target rather than once over the project path.
        """
        path = self.project_path
        return {
            "trivy-fs": [
                "trivy", "fs", "--format", "json",
                "--output", out_file, "--quiet", path,
            ],
            "checkov": [
                "checkov", "-d", path, "-o", "json",
                "--output-file", out_file, "--quiet",
            ],
            "secrets": [
                "trivy", "fs", "--scanners", "secret", "--format", "json",
                "--output", out_file, "--quiet", path,
            ],
        }

    def _run_one(self, label: str, cmd: list[str], out_file: str) -> Optional[str]:
        """Run a single scanner subprocess. Returns out_file on success/partial.

        Non-zero exits are logged but treated as non-fatal (partial results still
        merge). A missing executable is skipped gracefully. Returns None only when
        nothing usable was produced.
        """
        target = cmd[-1]
        _out(f"Running {label} on {target} ...")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCANNER_TIMEOUT_S,
                check=False,
            )
        except FileNotFoundError:
            _out(f"{cmd[0]} not found in PATH — skipping")
            return None
        except subprocess.TimeoutExpired:
            _out(f"{label}: timed out after {SCANNER_TIMEOUT_S}s — skipping")
            return None
        except OSError as exc:
            _out(f"{label}: failed to launch ({exc}) — skipping")
            return None

        count = self._count_findings(out_file)
        _out(f"{label}: {count} findings (exit {proc.returncode})")
        if proc.returncode != 0 and proc.stderr:
            _err(f"{label} stderr: {proc.stderr.strip()[:300]}")
        return out_file if Path(out_file).is_file() else None

    @staticmethod
    def _count_findings(out_file: str) -> int:
        """Best-effort count of findings in a scanner output file (for logging)."""
        try:
            findings = scan_merge._load_findings(out_file)
            return len(findings)
        except Exception:
            return 0

    def _url_targets(self) -> list[str]:
        """Return declared URL target values from the config."""
        targets = self.config.get("targets", []) or []
        return [
            t.get("value")
            for t in targets
            if isinstance(t, dict) and t.get("type") == "url" and t.get("value")
        ]

    def scan(self, output_dir: Optional[str] = None) -> str:
        """Run all detected scanners against the project. Returns merged JSON path.

        Each scanner writes to its own temp file; after all complete, the temp
        files are merged via scan_merge.merge_and_write into a single unified JSON
        under output_dir. Scanner-not-found and non-zero exits are non-fatal.
        """
        out_dir = output_dir or DEFAULT_OUTPUT_DIR
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        scanners = self.discover()["scanners"]
        if not scanners:
            _err("no scanners resolved for this project — nothing to run")

        tmp_dir = tempfile.mkdtemp(prefix="soc_scan_")
        produced: list[str] = []
        fs_commands = self._scanner_commands("")  # placeholder; rebuilt per-scanner

        # Always run the Python-native scanner first (no external tools required).
        try:
            py_out = scan_python.run_all(self.project_path, tmp_dir)
            if py_out and Path(py_out).is_file():
                produced.append(py_out)
        except Exception as exc:
            _err(f"python-scan: unexpected error ({exc}) — skipping")

        for scanner in scanners:
            if scanner == "nuclei":
                urls = self._url_targets()
                if not urls:
                    _out("nuclei: no URL targets declared — skipping")
                    continue
                for i, url in enumerate(urls):
                    out_file = str(Path(tmp_dir) / f"nuclei-{i}.json")
                    cmd = ["nuclei", "-u", url, "-json", "-o", out_file, "-silent"]
                    result = self._run_one("nuclei", cmd, out_file)
                    if result:
                        produced.append(result)
                continue

            if scanner == "trivy-image":
                image = self.config.get("image") or self.slug
                out_file = str(Path(tmp_dir) / "trivy-image.json")
                cmd = [
                    "trivy", "image", "--format", "json",
                    "--output", out_file, "--quiet", str(image),
                ]
                result = self._run_one("trivy-image", cmd, out_file)
                if result:
                    produced.append(result)
                continue

            if scanner == "python-scan":
                # Already ran above — skip duplicate.
                continue

            if scanner not in fs_commands:
                _out(f"{scanner}: unknown scanner type — skipping")
                continue

            out_file = str(Path(tmp_dir) / f"{scanner}.json")
            cmd = self._scanner_commands(out_file)[scanner]
            result = self._run_one(scanner, cmd, out_file)
            if result:
                produced.append(result)

        merged_path = scan_merge.merge_and_write(produced, out_dir, self.slug)
        _out(f"merged {len(produced)} scanner output(s) -> {merged_path}")
        return merged_path

    def run(self, output_dir: Optional[str] = None) -> str:
        """Full pipeline: scan → merge → return merged JSON path.

        The caller then passes the merged JSON to sic_to_soc.py to build the SOC
        handoff report.
        """
        return self.scan(output_dir=output_dir)


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
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run the detected scanners against the project.",
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help="With --scan: merge scanner outputs into one unified JSON (default behavior).",
    )
    parser.add_argument(
        "--output-dir",
        help=f"Directory for scan/merge artifacts (default: {DEFAULT_OUTPUT_DIR}).",
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

    if args.scan:
        # scan() always merges its outputs; --merge is accepted for explicitness.
        try:
            merged = runner.run(output_dir=args.output_dir)
        except Exception as exc:
            _err(f"scan failed: {exc}")
            return 1
        _out(f"done — merged findings at {merged}")
        return 0

    # Default + --describe: print the plan rather than silently doing nothing.
    runner.describe()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
