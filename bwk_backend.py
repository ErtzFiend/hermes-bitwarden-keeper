"""The ``bwk`` LoginBackend: browser_vault fills for all connected keeper accounts.

Handles are ``bwk:<account>:<item-id>``. Registration is best-effort: core
refuses the seam for local-directory installs (provenance gate), in which case
the plugin degrades to its own tool + CLI and browser fills keep using the
core ``bitwarden`` backend. The class itself follows the exact LoginBackend
contract (agent/vault_backends/base.py) and the registry's static-shape rules
(plain string class attributes, needs_unlock=False — plugin backends may not
use Hermes' master-password prompt; connect happens via the CLI).
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from typing import Optional

import bwk_core

from agent.vault_backends.base import LoginBackend, UnlockRequired
from agent.vault_store import VaultItemMeta, normalize_origin


class KeeperLoginBackend(LoginBackend):
    # Plain string class attributes (the registry inspects them statically).
    name = bwk_core.BACKEND_NAME
    display_name = bwk_core.DISPLAY_NAME
    prefix = bwk_core.handle_prefix()
    needs_unlock = False  # plugin rule: no Hermes master-password prompt

    def __init__(self, cfg: Optional[dict] = None):
        self.cfg = cfg if cfg is not None else None  # None -> lazy vault.bwk config

    def _cfg(self) -> dict:
        if self.cfg is not None:
            return self.cfg
        try:
            from hermes_cli.config import load_config_readonly
            vault = load_config_readonly().get("vault") or {}
            section = vault.get(bwk_core.BACKEND_NAME)
            return section if isinstance(section, dict) else {}
        except Exception:
            return {}

    def _connected_accounts(self) -> list[str]:
        store = bwk_core.AccountStore()
        names = []
        for name in store.names():
            if bwk_core.in_process_token() or bwk_core.restore_if_allowed(name, self._cfg()):
                names.append(name)
        return names

    def _token_for(self, account: str) -> Optional[str]:
        token = bwk_core.in_process_token()
        if token:
            return token
        if bwk_core.restore_if_allowed(account, self._cfg()):
            return bwk_core.in_process_token()
        return None

    # -- LoginBackend contract --------------------------------------------
    def is_unlocked(self) -> bool:
        return bool(self._connected_accounts())

    def fill_context(self):
        return nullcontext()

    def list_items(self) -> list[VaultItemMeta]:
        out: list[VaultItemMeta] = []
        for account in self._connected_accounts():
            try:
                raw = json.loads(bwk_core._run(
                    account, ["list", "items"], bwk_core.in_process_token(), self._cfg()) or "[]")
            except Exception:
                continue
            for item in raw if isinstance(raw, list) else []:
                if item.get("type") != 1:
                    continue
                login = item.get("login") or {}
                uris = []
                for u in (login.get("uris") or []):
                    uri = str(u.get("uri") or "") if isinstance(u, dict) else ""
                    if uri:
                        uris.append(uri)
                if login.get("uri"):
                    uris.insert(0, str(login["uri"]))
                origin = normalize_origin(uris[0]) if uris else None
                out.append(VaultItemMeta(
                    id=f"{self.prefix}{account}:{item.get('id')}",
                    kind="login",
                    label=str(item.get("name") or "(untitled)"),
                    origin=origin,
                    created_at=str(item.get("creationDate") or ""),
                    identifier=(str(login.get("username")) if login.get("username") else None),
                    identifier_type="username" if login.get("username") else None,
                    has_otp=bool(login.get("totp")),
                    allowed_origins=tuple({normalize_origin(u) for u in uris if normalize_origin(u)}),
                ))
        return out

    def get_meta(self, handle: str) -> Optional[VaultItemMeta]:
        account, item_id = bwk_core.split_handle(handle)
        if not item_id:
            return None
        token = self._token_for(account)
        if not token:
            return None
        try:
            raw = json.loads(bwk_core._run(account, ["get", "item", item_id],
                                           token, self._cfg()) or "null")
        except Exception:
            return None
        if not isinstance(raw, dict) or raw.get("type") != 1:
            return None
        login = raw.get("login") or {}
        uris = [str(u.get("uri") or "") for u in (login.get("uris") or []) if isinstance(u, dict)]
        if login.get("uri"):
            uris.insert(0, str(login["uri"]))
        origin = normalize_origin(uris[0]) if uris else None
        return VaultItemMeta(
            id=handle,
            kind="login",
            label=str(raw.get("name") or "(untitled)"),
            origin=origin,
            created_at=str(raw.get("creationDate") or ""),
            identifier=(str(login.get("username")) if login.get("username") else None),
            identifier_type="username" if login.get("username") else None,
            has_otp=bool(login.get("totp")),
            allowed_origins=tuple({normalize_origin(u) for u in uris if normalize_origin(u)}),
        )

    def resolve_password(self, handle: str) -> str:
        account, item_id = bwk_core.split_handle(handle)
        if not item_id:
            raise UnlockRequired(self)
        token = self._token_for(account)
        if not token:
            raise UnlockRequired(self)
        from agent.secret_sources.base import run_cli, scrub_ansi
        proc = run_cli([str(bwk_core.bw_binary(self._cfg())), "get", "password", item_id,
                        "--nointeraction"],
                       env=bwk_core._env(account, token), timeout=bwk_core.TIMEOUT,
                       label="bw", timeout_message="bw timed out", stdin=None)
        password = (proc.stdout or "").strip()
        if not password:
            raise RuntimeError("bw returned an empty password")
        try:
            from agent.redact import register_vault_redaction_value
            register_vault_redaction_value(password)
        except Exception:
            pass
        return password

    def resolve_otp(self, handle: str) -> Optional[str]:
        account, item_id = bwk_core.split_handle(handle)
        if not item_id:
            return None
        token = self._token_for(account)
        if not token:
            return None
        try:
            from agent.secret_sources.base import run_cli
            proc = run_cli([str(bwk_core.bw_binary(self._cfg())), "get", "totp", item_id,
                            "--nointeraction"],
                           env=bwk_core._env(account, token), timeout=bwk_core.TIMEOUT,
                           label="bw", timeout_message="bw timed out", stdin=None)
            if proc.returncode != 0:
                return None
            return (proc.stdout or "").strip() or None
        except Exception:
            return None
