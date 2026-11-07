"""Dashboard backend for `bitwarden-keeper`: account/session status only.

Routes mount under /api/plugins/bitwarden-keeper/:

    GET /status?probe=0|1   account rows; probe=1 additionally validates each
                            stored session with a bounded bw read (never
                            returns secret values)
    GET /health             state files present?

No mutation endpoints: connect/disconnect are deliberate user actions in the
CLI (passwords never cross the dashboard or the model). The desktop pane is
read-only plus links/instructions.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter

router = APIRouter()

_SAFE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")


def _home(profile: Optional[str] = None) -> Path:
    home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
    if profile and profile not in ("default", "") and _SAFE.match(profile):
        candidate = home / "profiles" / profile
        if candidate.is_dir():
            return candidate
    return home


def _state_root(profile: Optional[str] = None) -> Path:
    return _home(profile) / "bitwarden-keeper"


@router.get("/status")
async def status(profile: Optional[str] = None, probe: bool = False) -> dict:
    os.environ.setdefault("HERMES_HOME", str(_home(profile)))
    try:
        import bwk_core

        store = bwk_core.AccountStore()
        return {"ok": True, "default": store.default_name(),
                "accounts": store.status(probe=probe)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "accounts": []}


@router.get("/health")
async def health(profile: Optional[str] = None) -> dict:
    root = _state_root(profile)
    secrets = root.parent / "secrets" / "bitwarden-keeper"
    return {"ok": True, "state_root": str(root), "state_root_exists": root.is_dir(),
            "secrets_dir_exists": secrets.is_dir()}
