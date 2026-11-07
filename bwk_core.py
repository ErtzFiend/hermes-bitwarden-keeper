"""bitwarden-keeper core: multi-account Bitwarden sessions for Hermes.

Design mirrors the core vault unlock store (agent/vault_backends/unlock.py):

- In-process token holding is delegated to the core store, keyed by backend
  name ``bwk`` (profile-scoped there by HERMES_HOME). Locks bump a per-key
  generation, so an in-flight unlock can never commit over an acknowledged
  lock (``store_session_token(..., generation=...)`` fails instead).
- Cross-restart persistence per account is two credential-free-of-JSON files:
  ``<HERMES_HOME>/secrets/bitwarden-keeper/<account>.session`` (0600, the raw
  BW_SESSION token — the same protected-at-rest trade-off the core backend's
  shared cache makes) and ``<account>.persist`` (0600, permission marker with
  NO credentials). Restore is gated on the marker; explicit disconnect deletes
  both, so a stolen marker alone is useless.
- Per-account isolation uses ``BITWARDENCLI_APPDATA_DIR`` (honored by bw
  v2026.9.0): every account has its own 0700 appdata dir, so multiple accounts
  hold simultaneous independent sessions.
- Secrets never appear in argv. ``bw unlock`` is fed via ``--passwordenv``;
  every other call takes ``BW_SESSION`` through the child environment only.

Accounts metadata (no secrets) lives in
``<HERMES_HOME>/bitwarden-keeper/accounts.json`` (0600).
"""

from __future__ import annotations

import fcntl
import getpass
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

BACKEND_NAME = "bwk"           # vault.<bwk>.* config key; handle prefix bwk:
DISPLAY_NAME = "Bitwarden Keeper"
TIMEOUT = 30.0
PROBE_SEARCH = "__bwk_probe_5f2a__"

_ENV_KEEP = ("PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SystemRoot",
             "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "BITWARDENCLI_APPDATA_DIR")
_ACCOUNT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_MASTER_ENV = "HERMES_BW_KEEPER_MASTER"


def hermes_home() -> Path:
    from hermes_constants import get_hermes_home
    try:
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def keeper_root() -> Path:
    return hermes_home() / "bitwarden-keeper"


def secrets_root() -> Path:
    return hermes_home() / "secrets" / "bitwarden-keeper"


def _write_0600(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def _read_0600(path: Path) -> Optional[str]:
    try:
        if path.is_file() and (path.stat().st_mode & 0o077) == 0:
            return path.read_text().strip() or None
    except OSError:
        pass
    return None


def account_lock_path(account: str) -> Path:
    digest = hashlib.sha256(account.encode()).hexdigest()[:12]
    return Path("/run/lock") / f"bwk-{digest}.lock"


# ---------------------------------------------------------------- accounts ---

class AccountStore:
    """Accounts metadata (no secrets) + per-account session file helpers."""

    def __init__(self, home: Optional[Path] = None):
        self.home = Path(home) if home else hermes_home()
        self.root = self.home / "bitwarden-keeper"
        self.secrets = self.home / "secrets" / "bitwarden-keeper"
        self.accounts_file = self.root / "accounts.json"
        self._lock = threading.Lock()
        self._accounts: Dict[str, Dict[str, Any]] = self._load()

    # -- persistence ------------------------------------------------------
    def _load(self) -> Dict[str, Dict[str, Any]]:
        try:
            data = json.loads(self.accounts_file.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_0600(self.accounts_file, json.dumps(self._accounts, indent=2, sort_keys=True))

    # -- CRUD -------------------------------------------------------------
    def _check_name(self, name: str) -> str:
        name = str(name or "").strip().lower()
        if not _ACCOUNT_RE.fullmatch(name):
            raise ValueError("account name must be 1-64 chars: a-z 0-9 _ - (starts alphanumeric)")
        return name

    def add(self, name: str, appdata_dir: Optional[str] = None,
            server_url: Optional[str] = None) -> str:
        with self._lock:
            name = self._check_name(name)
            if name in self._accounts:
                raise ValueError(f"account {name!r} already exists")
            acct_dir = Path(appdata_dir).expanduser() if appdata_dir else (
                self.root / name / "appdata")
            self._accounts[name] = {
                "appdata_dir": str(acct_dir),
                "server_url": (server_url or "").strip() or None,
                "default": not self._accounts,
            }
            self._save()
        acct_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return handle_prefix() + name

    def remove(self, name: str) -> None:
        with self._lock:
            name = self._check_name(name)
            if name not in self._accounts:
                raise ValueError(f"account {name!r} does not exist")
            del self._accounts[name]
            if self._accounts and not any(a.get("default") for a in self._accounts.values()):
                next_name = sorted(self._accounts)[0]
                self._accounts[next_name]["default"] = True
            self._save()
        self.clear_session_files(name)

    def set_default(self, name: str) -> None:
        with self._lock:
            name = self._check_name(name)
            if name not in self._accounts:
                raise ValueError(f"account {name} does not exist")
            for acct in self._accounts.values():
                acct["default"] = False
            self._accounts[name]["default"] = True
            self._save()

    def names(self) -> List[str]:
        return sorted(self._accounts)

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self._accounts.get(name)

    def default_name(self) -> Optional[str]:
        for name, acct in self._accounts.items():
            if acct.get("default"):
                return name
        return self.names()[0] if self._accounts else None

    def require(self, name: Optional[str]) -> str:
        name = name or self.default_name()
        if not name:
            raise ValueError("no bitwarden-keeper accounts; add one first "
                             "(`hermes bitwarden-keeper add <name>`)")
        name = self._check_name(name)
        if name not in self._accounts:
            raise ValueError(f"account {name!r} does not exist")
        return name

    def appdata_dir(self, name: str) -> Path:
        acct = self._accounts.get(name) or {}
        return Path(acct.get("appdata_dir") or (self.root / name / "appdata"))

    # -- session files (0600 token + credential-free persist marker) ------
    def session_file(self, name: str) -> Path:
        return self.secrets / f"{name}.session"

    def persist_marker(self, name: str) -> Path:
        return self.secrets / f"{name}.persist"

    def read_session_file(self, name: str) -> Optional[str]:
        return _read_0600(self.session_file(name))

    def write_session_file(self, name: str, token: str) -> None:
        _write_0600(self.session_file(name), token)

    def clear_session_files(self, name: str) -> None:
        name = self._check_name(name)
        for p in (self.session_file(name), self.persist_marker(name)):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def status(self, probe: bool = False) -> List[Dict[str, Any]]:
        out = []
        for name in self.names():
            acct = self._accounts[name]
            row = {
                "name": name,
                "default": bool(acct.get("default")),
                "server_url": acct.get("server_url") or "bitwarden.com",
                "appdata_dir": acct["appdata_dir"],
                "session_file": self.session_file(name).is_file(),
                "persist_marker": self.persist_marker(name).is_file(),
            }
            if probe:
                row["valid"] = session_valid(name)
            out.append(row)
        return out


def handle_prefix() -> str:
    return BACKEND_NAME + ":"


def split_handle(handle: str) -> tuple[str, Optional[str]]:
    """``bwk:<account>`` / ``bwk:<account>:<item-id>`` -> (account, item_id|None).

    A handle without this backend's prefix is returned verbatim as the account
    slot (the caller's require() then rejects it) — never silently split.
    """
    if not handle.startswith(handle_prefix()):
        return handle, None
    body = handle[len(handle_prefix()):]
    parts = body.split(":", 1)
    account = parts[0]
    item = parts[1] if len(parts) > 1 and parts[1] else None
    return account, item


# ------------------------------------------------------------- bw process ---

def _env(account: str, token: Optional[str]) -> Dict[str, str]:
    store = AccountStore()
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env["NO_COLOR"] = "1"
    env["BITWARDENCLI_APPDATA_DIR"] = str(store.appdata_dir(account))
    if token:
        env["BW_SESSION"] = token
    return env


def bw_binary(cfg: Optional[dict] = None) -> Path:
    import shutil
    explicit = str((cfg or {}).get("binary_path") or "") or shutil.which("bw")
    if not explicit:
        raise RuntimeError("Bitwarden CLI (bw) not found — install it or set vault.bwk.binary_path")
    return Path(explicit)


def _run(account: str, argv: List[str], token: Optional[str], cfg: Optional[dict],
         timeout: float = TIMEOUT) -> str:
    """Run a bw command for one account; returns stdout. Raises on failure or a
    stale/absent session (mirrors the core backend's _run contract)."""
    from agent.secret_sources.base import run_cli, scrub_ansi
    token = token if token is not None else in_process_token()
    if not token:
        from agent.vault_backends.base import UnlockRequired
        raise UnlockRequired(type("_BwkLocked", (), {"display_name": DISPLAY_NAME})())
    proc = run_cli([str(bw_binary(cfg)), *argv, "--nointeraction"], env=_env(account, token),
                   timeout=timeout, label="bw", timeout_message="bw timed out",
                   stdin=subprocess.DEVNULL)
    if proc.returncode != 0:
        err = scrub_ansi(proc.stderr or "")
        if "locked" in err.lower() or "session" in err.lower():
            in_process_lock()
            from agent.vault_backends.base import UnlockRequired
            raise UnlockRequired(type("_BwkLocked", (), {"display_name": DISPLAY_NAME})())
        raise RuntimeError(f"bw failed: {err[:200]}")
    return proc.stdout or ""


def session_valid(account: str, token: Optional[str] = None,
                  cfg: Optional[dict] = None, store: Optional[AccountStore] = None) -> bool:
    """A server-bound read that must return a well-formed empty list."""
    token = token or in_process_token()
    if not token:
        return False
    try:
        out = _run(account, ["list", "items", "--search", PROBE_SEARCH],
                   token, cfg, timeout=40.0)
    except Exception:
        return False
    return out.strip() == "[]"


def in_process_token() -> Optional[str]:
    try:
        from agent.vault_backends import unlock as _unlock
        return _unlock.get_session_token(BACKEND_NAME)
    except Exception:
        return None


def in_process_store_token(token: str, generation: Optional[int] = None,
                           restore: bool = False) -> bool:
    """Commit to the core unlock store. Older/upstream stores lack the
    ``restore`` kwarg (marker-gated restore is enforced at THIS layer
    anyway), so fall back to the plain signature instead of failing."""
    try:
        from agent.vault_backends import unlock as _unlock
        try:
            return _unlock.store_session_token(BACKEND_NAME, token, generation, restore=restore)
        except TypeError:
            return _unlock.store_session_token(BACKEND_NAME, token, generation)
    except Exception:
        return False


def in_process_begin() -> int:
    try:
        from agent.vault_backends import unlock as _unlock
        return _unlock.begin_unlock(BACKEND_NAME)
    except Exception:
        return 0


def in_process_lock() -> None:
    """Bump the fence generation; in-flight unlocks can no longer commit."""
    try:
        from agent.vault_backends import unlock as _unlock
        _unlock.lock(BACKEND_NAME)
    except Exception:
        pass


# ---------------------------------------------------------------- connect ---

def connect(account: Optional[str] = None, master_password: Optional[str] = None,
            interactive: bool = False, cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Unlock one account and persist the session until explicit disconnect.

    Single minter per account: serialized on a per-account flock (a second
    ``bw unlock`` supersedes the first's token). Reuses the stored session
    when it still validates, so repeated connects mint nothing.
    """
    store = AccountStore()
    account = store.require(account)
    lock_fh = open(account_lock_path(account), "a+")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        cached = store.read_session_file(account)
        if cached and session_valid(account, cached, cfg, store):
            generation = in_process_begin()
            if not in_process_store_token(cached, generation):
                return {"success": False, "error": "locked while connecting; try again"}
            store.persist_marker(account).touch(mode=0o600, exist_ok=True)
            return {"success": True, "account": account, "minted": False,
                    "message": "existing session still valid; nothing minted"}

        if master_password is None:
            master_password = os.environ.get(_MASTER_ENV) or ""
        if not master_password and interactive and sys.stdin.isatty():
            master_password = getpass.getpass(f"Bitwarden master password for {account!r}: ")
        if not master_password:
            raise ValueError("no master password (set HERMES_BW_KEEPER_MASTER or run "
                             "interactively in a terminal)")

        generation = in_process_begin()
        from agent.secret_sources.base import run_cli, scrub_ansi
        from agent.vault_backends.base import run_with_secret_env
        proc = run_with_secret_env(
            [str(bw_binary(cfg)), "unlock", "--raw", "--nointeraction",
             "--passwordenv", _MASTER_ENV],
            env=_env(account, None), secret_env=_MASTER_ENV, secret=master_password,
            timeout=60.0, label="bw")
        token = (proc.stdout or "").strip()
        if proc.returncode != 0 or not token:
            err = scrub_ansi(proc.stderr or "").strip()[:200]
            if "not logged in" in err.lower():
                err = "not logged in — run `bw login` once in this account's terminal first"
            raise RuntimeError(f"bw unlock failed: {err or 'no session key'}")
        store.write_session_file(account, token)
        store.persist_marker(account).touch(mode=0o600, exist_ok=True)
        if not in_process_store_token(token, generation):
            return {"success": False, "error": "locked while connecting; try again"}
        return {"success": True, "account": account, "minted": True,
                "message": "connected; the session persists until you disconnect it"}
    finally:
        lock_fh.close()


def disconnect(account: Optional[str] = None, logout: bool = False,
               cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Explicit disconnect: delete the persist marker + session file and fence
    in-flight commits by bumping the generation. With ``logout`` also log the
    account's appdata out of bw."""
    store = AccountStore()
    account = store.require(account)
    in_process_lock()
    store.clear_session_files(account)
    out: Dict[str, Any] = {"success": True, "account": account, "disconnected": True}
    if logout:
        try:
            # logout needs no session — plain child env, no BW_SESSION.
            from agent.secret_sources.base import run_cli, scrub_ansi
            proc = run_cli([str(bw_binary(cfg)), "logout", "--nointeraction"],
                           env=_env(account, None), timeout=TIMEOUT, label="bw",
                           timeout_message="bw timed out", stdin=subprocess.DEVNULL)
            if proc.returncode != 0:
                raise RuntimeError(scrub_ansi(proc.stderr or "")[:200])
            out["logged_out"] = True
        except Exception as exc:  # logout is best-effort; the disconnect already happened
            out["logged_out"] = False
            out["logout_error"] = str(exc)[:200]
    return out


def restore_if_allowed(account: Optional[str] = None, cfg: Optional[dict] = None) -> bool:
    """Cross-restart restore, gated on the persist marker (no marker, no restore)."""
    store = AccountStore()
    account = store.require(account)
    if not store.persist_marker(account).is_file():
        return False
    cached = store.read_session_file(account)
    if not cached:
        return False
    if in_process_token():
        return True
    if not session_valid(account, cached, cfg, store):
        return False
    return in_process_store_token(cached, restore=True)


def adopt_existing(account: str, cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Register the machine's existing default-appdata Bitwarden account.

    The bw CLI state stays where it is (we never move or read another
    backend's session here); the keeper just starts managing THIS account's
    own sessions. Connect afterwards to mint/persist a keeper session.
    """
    default_appdata = os.environ.get("BITWARDENCLI_APPDATA_DIR") or ""
    store = AccountStore()
    handle = store.add(account, appdata_dir=default_appdata or None)
    return {"success": True, "account": account, "handle": handle,
            "appdata_dir": str(store.appdata_dir(account)),
            "message": "adopted existing bw appdata; run `hermes bitwarden-keeper connect "
                       f"{account}` to sign in (stays signed in until you disconnect)"}
