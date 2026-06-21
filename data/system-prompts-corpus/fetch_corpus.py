#!/usr/bin/env python3
"""Fetch the system-prompts red-team corpus on demand.

Clones asgeirtj/system_prompts_leaks (CC0 1.0) into the gitignored `_clone/`
directory next to this script. The raw files are intentionally not vendored
into the repo — `manifest.json` is the committed source of truth (id, title,
path, github_url, sha256, preview for all 255 entries); this script pulls the
full text when red-team tooling needs it.

Usage:
    python fetch_corpus.py            # clone or update
    python fetch_corpus.py --verify   # verify clone against manifest sha256
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLONE_DIR = HERE / "_clone"
MANIFEST = HERE / "manifest.json"
UPSTREAM = "https://github.com/asgeirtj/system_prompts_leaks"


def fetch() -> None:
    if (CLONE_DIR / ".git").exists():
        print(f"Updating existing clone in {CLONE_DIR} ...")
        subprocess.run(["git", "-C", str(CLONE_DIR), "pull", "--ff-only"], check=True)
    else:
        print(f"Cloning {UPSTREAM} into {CLONE_DIR} ...")
        subprocess.run(["git", "clone", "--depth", "1", UPSTREAM, str(CLONE_DIR)], check=True)
    print("Done.")


def verify() -> int:
    if not MANIFEST.exists():
        print("manifest.json missing", file=sys.stderr)
        return 2
    if not CLONE_DIR.exists():
        print("Clone missing — run `python fetch_corpus.py` first.", file=sys.stderr)
        return 2
    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mismatched = 0
    missing = 0
    for e in entries:
        f = CLONE_DIR / e["path"]
        if not f.exists():
            missing += 1
            continue
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        if digest != e["sha256"]:
            mismatched += 1
            print(f"  sha mismatch: {e['path']}")
    print(f"Verified {len(entries)} entries: {missing} missing, {mismatched} changed upstream.")
    return 1 if (missing or mismatched) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch/verify the system-prompts red-team corpus.")
    ap.add_argument("--verify", action="store_true", help="verify clone against manifest sha256")
    args = ap.parse_args()
    if args.verify:
        return verify()
    fetch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
