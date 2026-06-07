"""
project_config.py — Per-project `.sic.yaml` config + global project registry.

Provides:
  - load_config / detect_project_type — read a project's scan config, auto-detecting
    sensible scanner defaults when no `.sic.yaml` is present.
  - register_project / list_projects / get_project — upsert + read the global
    registry at `~/.sic/projects.json`.
  - is_suppressed — match a finding against a project's suppression rules, honoring
    expiry dates.

YAML parsing prefers PyYAML when installed; falls back to a minimal manual parser
that understands the documented `.sic.yaml` schema (no anchors, flow style, etc.).

Requirements: stdlib + optional `pyyaml`. Errors are written to stderr.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

try:
    import yaml as _yaml  # type: ignore

    _HAS_YAML = True
except ImportError:  # pragma: no cover - depends on environment
    _yaml = None  # type: ignore
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REGISTRY_PATH: Path = Path.home() / ".sic" / "projects.json"
CONFIG_FILENAME: str = ".sic.yaml"

VALID_ASSET_TIERS: tuple[str, ...] = ("production", "staging", "internal", "dev")

# Source-file suffixes scanned for content-detection signals. Broadened beyond
# the original .py/.ts pair so polyglot repos (Go, Rust, frontend, templates)
# are profiled correctly.
CONTENT_SUFFIXES: tuple[str, ...] = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java",
    ".html", ".vue", ".svelte",
)
# Directories never worth grepping — vendored deps, build output, archives.
SKIP_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", "dist", ".next", "_archive", "__pycache__", ".venv"}
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    """Write a namespaced error line to stderr."""
    print(f"[project_config] {msg}", file=sys.stderr)


def _today() -> date:
    """Return today's date (kept as a seam for testing)."""
    return date.today()


def _parse_date(value: Any) -> Optional[date]:
    """Parse a YYYY-MM-DD string (or date) into a date. Returns None on failure."""
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        _err(f"could not parse expiry date: {value!r}")
        return None


# ---------------------------------------------------------------------------
# Minimal YAML fallback parser
# ---------------------------------------------------------------------------


def _coerce_scalar(token: str) -> Any:
    """Coerce a bare YAML scalar token into a Python value."""
    token = token.strip()
    if (token.startswith('"') and token.endswith('"')) or (
        token.startswith("'") and token.endswith("'")
    ):
        return token[1:-1]
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _fallback_yaml_parse(text: str) -> dict[str, Any]:
    """Parse the documented `.sic.yaml` schema without PyYAML.

    Supports top-level scalars, top-level lists of mappings (one item per
    `- key: value` block), and nested mapping keys under a list item. Does not
    support advanced YAML features — only the shape this project emits.
    """
    root: dict[str, Any] = {}
    current_key: Optional[str] = None  # active top-level list key
    current_list: Optional[list[dict[str, Any]]] = None
    current_item: Optional[dict[str, Any]] = None

    for raw_line in text.splitlines():
        # Strip comments (only when not inside quotes — schema has no inline-# values).
        line = raw_line.split("#", 1)[0].rstrip() if "#" in raw_line else raw_line.rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0 and not stripped.startswith("-"):
            # Top-level key.
            if ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            current_key = key
            current_item = None
            if val == "":
                # Container (list or nested) — assume list per schema.
                current_list = []
                root[key] = current_list
            else:
                root[key] = _coerce_scalar(val)
                current_list = None
            continue

        if stripped.startswith("-"):
            # New list item; may carry an inline `key: value`.
            if current_list is None:
                if current_key is not None:
                    current_list = []
                    root[current_key] = current_list
                else:
                    continue
            current_item = {}
            current_list.append(current_item)
            body = stripped[1:].strip()
            if body:
                if ":" in body:
                    k, _, v = body.partition(":")
                    current_item[k.strip()] = _coerce_scalar(v)
                else:
                    # Bare scalar list item — represent as {"value": scalar}.
                    current_item["value"] = _coerce_scalar(body)
            continue

        # Indented key under the current list item.
        if current_item is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            current_item[k.strip()] = _coerce_scalar(v)

    return root


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse YAML text into a dict, using PyYAML when available."""
    if _HAS_YAML:
        try:
            data = _yaml.safe_load(text)  # type: ignore[union-attr]
            return data if isinstance(data, dict) else {}
        except Exception as exc:  # pragma: no cover - malformed user yaml
            _err(f"PyYAML failed to parse config, falling back: {exc}")
    try:
        return _fallback_yaml_parse(text)
    except Exception as exc:
        _err(f"fallback YAML parse failed: {exc}")
        return {}


# ---------------------------------------------------------------------------
# Global registry
# ---------------------------------------------------------------------------


def _load_registry() -> dict[str, Any]:
    """Load the registry file, returning a default shape on any error."""
    if not REGISTRY_PATH.exists():
        return {"projects": []}
    try:
        with REGISTRY_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not isinstance(data.get("projects"), list):
            _err("registry file malformed; resetting to empty registry")
            return {"projects": []}
        return data
    except (OSError, json.JSONDecodeError) as exc:
        _err(f"could not read registry: {exc}")
        return {"projects": []}


def _save_registry(registry: dict[str, Any]) -> None:
    """Write the registry to disk, creating the parent dir if needed."""
    try:
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with REGISTRY_PATH.open("w", encoding="utf-8") as fh:
            json.dump(registry, fh, indent=2, sort_keys=False)
            fh.write("\n")
    except OSError as exc:
        _err(f"could not write registry: {exc}")


def register_project(slug: str, path: str, config_path: str) -> None:
    """Upsert a project into the global registry, keyed by slug."""
    if not slug:
        _err("register_project called with empty slug; ignoring")
        return
    registry = _load_registry()
    projects: list[dict[str, Any]] = registry["projects"]
    entry = {
        "slug": slug,
        "path": str(path),
        "config_path": str(config_path),
        "last_seen": _today().isoformat(),
    }
    for i, existing in enumerate(projects):
        if existing.get("slug") == slug:
            projects[i] = entry
            break
    else:
        projects.append(entry)
    _save_registry(registry)


def _slug_from_remote_url(url: str) -> Optional[str]:
    """Extract a normalized repo slug from a git remote URL.

    e.g. https://github.com/turdpusher360/drop_stream(.git) -> 'drop-stream'
         git@github.com:Org/My_Repo.git                     -> 'my-repo'
    Returns None if no repo name can be extracted.
    """
    url = (url or "").strip()
    if not url:
        return None
    # Strip trailing .git, then take the last path/colon-delimited segment.
    cleaned = re.sub(r"\.git$", "", url, flags=re.IGNORECASE)
    cleaned = cleaned.rstrip("/")
    # Last segment after the final '/' or ':'.
    segment = re.split(r"[/:]", cleaned)[-1] if cleaned else ""
    segment = segment.strip()
    if not segment:
        return None
    slug = re.sub(r"[^a-z0-9]+", "-", segment.lower()).strip("-")
    return slug or None


def register_from_git(path: str) -> Optional[dict[str, Any]]:
    """Run `git remote get-url origin` in path, extract slug, register project.

    e.g. https://github.com/turdpusher360/drop_stream -> slug=drop-stream

    Returns the registered project dict (as stored in the registry) or None on
    failure. All errors are written to stderr; this function never raises.
    """
    root = Path(path)
    if not root.exists() or not root.is_dir():
        _err(f"register_from_git: path not a directory: {path}")
        return None

    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _err(f"register_from_git: git invocation failed for {path}: {exc}")
        return None

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        _err(f"register_from_git: no origin remote in {path}: {stderr or 'unknown error'}")
        return None

    url = (result.stdout or "").strip()
    slug = _slug_from_remote_url(url)
    if not slug:
        _err(f"register_from_git: could not derive slug from remote url: {url!r}")
        return None

    config_file = root / CONFIG_FILENAME
    config_path = str(config_file) if config_file.is_file() else ""
    register_project(slug, str(root), config_path)
    return get_project(slug)


def list_projects() -> list[dict[str, Any]]:
    """Return all registered projects."""
    return _load_registry()["projects"]


def get_project(slug: str) -> Optional[dict[str, Any]]:
    """Return a single registered project by slug, or None if not found."""
    for project in _load_registry()["projects"]:
        if project.get("slug") == slug:
            return project
    return None


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------


def detect_project_type(path: str) -> list[str]:
    """Detect what scanners to run based on project files present.

    Returns list of scanner types: 'checkov', 'trivy-fs', 'trivy-image',
    'nuclei', 'secrets'.

    Detection rules:
    - wrangler.toml present -> ['checkov', 'secrets']  (CF Workers)
    - package.json present -> ['trivy-fs', 'secrets']
    - Dockerfile present -> ['trivy-image', 'checkov']
    - pyproject.toml or requirements.txt -> ['trivy-fs', 'secrets']
    - .tf files present -> ['checkov', 'secrets']
    - target URLs present -> ['nuclei']  (resolved by load_config, not here)
    """
    root = Path(path)
    scanners: list[str] = []

    def _add(*names: str) -> None:
        for name in names:
            if name not in scanners:
                scanners.append(name)

    if not root.exists() or not root.is_dir():
        _err(f"detect_project_type: path not a directory: {path}")
        return scanners

    try:
        if (root / "wrangler.toml").is_file():
            _add("checkov", "secrets")
        if (root / "package.json").is_file():
            _add("trivy-fs", "secrets")
        if (root / "Dockerfile").is_file():
            _add("trivy-image", "checkov")
        if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
            _add("trivy-fs", "secrets")
        # Terraform: any .tf file at the project root.
        if any(p.suffix == ".tf" for p in root.glob("*.tf")):
            _add("checkov", "secrets")
    except OSError as exc:
        _err(f"detect_project_type: error scanning {path}: {exc}")

    return scanners


def detect_system_profile(path: str) -> dict:
    """Detect system components and scanners from project filesystem + content signals.

    Returns:
        {"components": [<component_key>, ...], "scanners": [<scanner_id>, ...]}
        Components match keys in threat_catalog.SYSTEM_COMPONENTS.
    """
    import re as _re

    root = Path(path)
    components: list[str] = []
    scanners: list[str] = detect_project_type(path)

    def _add_component(name: str) -> None:
        if name not in components:
            components.append(name)

    def _grep(pattern: str, *files: str) -> bool:
        rx = _re.compile(pattern, _re.IGNORECASE)
        for fname in files:
            fpath = root / fname
            try:
                if fpath.is_file() and rx.search(
                    fpath.read_text(encoding="utf-8", errors="ignore")
                ):
                    return True
            except OSError:
                pass
        return False

    def _grep_any(pattern: str) -> bool:
        rx = _re.compile(pattern, _re.IGNORECASE)
        for fpath in root.rglob("*"):
            if fpath.suffix.lower() not in CONTENT_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in fpath.parts):
                continue
            try:
                if fpath.is_file() and rx.search(
                    fpath.read_text(encoding="utf-8", errors="ignore")
                ):
                    return True
            except OSError:
                pass
        return False

    # CF Workers
    if (root / "wrangler.toml").is_file():
        _add_component("cf-workers")
        _add_component("edge-runtime")

    # Durable Objects
    if _grep(r"DurableObject|durableObject|DO\b", "wrangler.toml") or _grep_any(
        r"DurableObject"
    ):
        _add_component("durable-objects")

    # Token / JWT auth
    if _grep_any(
        r"HMAC|jsonwebtoken|jwt\.sign|jwt\.verify|JWT_SECRET|refreshToken|access_token"
    ):
        _add_component("token-auth")

    # Object storage (R2 / S3)
    if _grep_any(
        r"\bR2\b|\.r2\.|s3\.amazonaws|S3Client|presign|PutObject|GetObject|R2Bucket"
    ):
        _add_component("object-storage")

    # SQL / D1
    if any(root.glob("*.sql")) or _grep_any(
        r"\.prepare\(|D1Database|sqlite|FROM\s+\w+\s+WHERE"
    ):
        _add_component("sql")

    # Docker
    if (root / "Dockerfile").is_file() or any(root.glob("docker-compose*.yml")):
        _add_component("docker")

    # OAuth (Google / Discord / GitHub)
    if _grep_any(
        r"oauth|discord\.com/api/oauth|accounts\.google\.com|github\.com/login/oauth"
    ):
        _add_component("oauth")

    # Stripe
    if _grep_any(r"stripe|Stripe|constructEvent|checkout\.sessions\.create"):
        _add_component("stripe")

    # WebSocket
    if _grep_any(r"WebSocket|ws://|wss://|upgrade.*websocket|Durable.*WebSocket"):
        _add_component("websocket")

    # Public web (Next.js, Vite, HTML)
    if (
        (root / "next.config.ts").is_file()
        or (root / "next.config.js").is_file()
        or (root / "vite.config.ts").is_file()
        or any(root.glob("*.html"))
    ):
        _add_component("public-web")

    # Secrets store signals (any project with .env / secret files)
    if (
        (root / ".env").is_file()
        or (root / ".env.example").is_file()
        or any(root.glob("*.env*"))
    ):
        _add_component("secrets-store")

    # Application server (FastAPI / Hono / Express / generic HTTP listener)
    if _grep_any(
        r"from\s+fastapi|new\s+Hono\(|express\(\)|app\.listen|FastAPI\("
    ):
        _add_component("app-server")

    return {"components": components, "scanners": scanners}


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _has_url_targets(config: dict[str, Any]) -> bool:
    """Return True if the config declares at least one URL target."""
    for target in config.get("targets", []) or []:
        if isinstance(target, dict) and target.get("type") == "url":
            return True
    return False


def load_config(project_path: str) -> dict[str, Any]:
    """Load `.sic.yaml` from project_path, return parsed config.

    Falls back to auto-detected defaults if no `.sic.yaml` is found. The returned
    dict always carries a `scanners` key (the effective scanner list) and a
    `_source` key ('file' | 'auto') describing where the config came from.
    """
    root = Path(project_path)
    config_file = root / CONFIG_FILENAME

    config: dict[str, Any]
    source: str

    if config_file.is_file():
        try:
            text = config_file.read_text(encoding="utf-8")
            config = _parse_yaml(text)
            source = "file"
        except OSError as exc:
            _err(f"could not read {config_file}: {exc}")
            config = {}
            source = "auto"
    else:
        config = {}
        source = "auto"

    # Normalize core shape.
    config.setdefault("slug", root.name)
    config.setdefault("name", root.name)
    config.setdefault("asset_tier", "dev")
    config.setdefault("targets", [])
    config.setdefault("suppressions", [])

    if config.get("asset_tier") not in VALID_ASSET_TIERS:
        _err(
            f"asset_tier {config.get('asset_tier')!r} invalid; "
            f"expected one of {VALID_ASSET_TIERS}. Defaulting to 'dev'."
        )
        config["asset_tier"] = "dev"

    # Resolve effective scanner list: explicit config wins, else auto-detect.
    scanners: list[str] = list(config.get("scanners") or [])
    if not scanners:
        scanners = detect_project_type(str(root))
    # URL targets always imply nuclei.
    if _has_url_targets(config) and "nuclei" not in scanners:
        scanners.append("nuclei")

    config["scanners"] = scanners
    config["_source"] = source
    config["_project_path"] = str(root)
    config["_config_path"] = str(config_file) if config_file.is_file() else None

    return config


def is_suppressed(finding: dict[str, Any], config: dict[str, Any]) -> bool:
    """Check if a finding matches a non-expired suppression rule.

    A finding is suppressed when its `cve` or `check_id` matches a suppression
    entry whose `expires` date is today or later (or absent). Suppressions whose
    expiry is in the past are treated as expired and ignored.
    """
    suppressions = config.get("suppressions") or []
    if not suppressions:
        return False

    finding_cve = finding.get("cve")
    finding_check = finding.get("check_id")
    today = _today()

    for rule in suppressions:
        if not isinstance(rule, dict):
            continue

        expires = _parse_date(rule.get("expires"))
        if expires is not None and expires < today:
            # Expired suppression — no longer active.
            continue

        rule_cve = rule.get("cve")
        rule_check = rule.get("check_id")

        if rule_cve and finding_cve and rule_cve == finding_cve:
            return True
        if rule_check and finding_check and rule_check == finding_check:
            return True

    return False
