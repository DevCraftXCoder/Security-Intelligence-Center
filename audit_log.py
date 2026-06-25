"""Durable audit log — append-only JSONL per day under logs/audit/."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()
_LOG_DIR = Path(__file__).parent / "logs" / "audit"


def audit_log(event: str, **kwargs: object) -> None:
    """Append one audit entry. Never raises — failures are silently swallowed."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_file = _LOG_DIR / f"{today}.jsonl"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **{k: v for k, v in kwargs.items() if v is not None},
        }
        line = json.dumps(entry, default=str) + "\n"
        with _lock:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:  # noqa: BLE001
        import sys as _sys  # noqa: PLC0415
        print(f"[audit_log] WARNING: write failed — {exc}", file=_sys.stderr)
