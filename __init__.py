"""bitwarden-keeper — Hermes plugin entry point.

Persistent single sign-in for Bitwarden: connect once and the session is
restored across restarts until you explicitly disconnect it. Multiple
accounts, each with its own isolated bw appdata dir, managed side by side;
a desktop configuration pane and a status chip ride along.

Surfaces wired here:
- a vault LoginBackend (``bwk:`` handles) for browser_vault fills — subject to
  Hermes' login-backend provenance gate: local-directory installs are refused
  the seam by core (documented, not worked around), so registration is
  best-effort and degrades to tool access only;
- the ``bitwarden-keeper`` tool (status/add/remove/use/adopt/connect-hint);
- the ``hermes bitwarden-keeper`` CLI (full account management);
- a dashboard status API for the desktop pane.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

TOOL_NAME = "bitwarden-keeper"

_ACTIONS = ("status", "add", "remove", "use", "adopt", "connect", "disconnect", "logout")

_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Manage persistent Bitwarden keeper accounts: status, add/remove accounts, "
        "set the default, adopt the machine's existing bw account, or disconnect. "
        "Passwords are NEVER handled through this tool: initial sign-in happens in a "
        "terminal via `hermes bitwarden-keeper connect <account>` (the session then "
        "persists until disconnect)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": list(_ACTIONS),
                "description": "status | add | remove | use (set default) | adopt | "
                               "connect | disconnect | logout",
            },
            "account": {"type": "string", "description": "account name (default: the default account)"},
            "server_url": {"type": "string", "description": "add: custom Bitwarden server URL (self-hosted)"},
            "logout": {"type": "boolean", "description": "disconnect: also `bw logout` that account's appdata"},
        },
        "required": ["action"],
    },
}


def _tool_handler(params: Dict[str, Any], **kwargs) -> str:
    import bwk_core

    action = str(params.get("action") or "").strip()
    account = (params.get("account") or "").strip() or None
    try:
        store = bwk_core.AccountStore()
        if action == "status":
            probe = bool(params.get("probe")) if isinstance(params.get("probe"), bool) else False
            return json.dumps({"success": True, "default": store.default_name(),
                               "accounts": store.status(probe=probe)}, indent=2)
        if action == "add":
            handle = store.add(account or "", server_url=params.get("server_url"))
            return json.dumps({"success": True, "handle": handle,
                               "message": "added. To sign in: run `hermes bitwarden-keeper "
                                          f"connect {account}` in a terminal (type the master "
                                          "password there); it stays signed in until disconnect."})
        if action == "remove":
            store.remove(bwk_core.AccountStore().require(account))
            return json.dumps({"success": True, "removed": account})
        if action == "use":
            store.set_default(store.require(account))
            return json.dumps({"success": True, "default": store.default_name()})
        if action == "adopt":
            return json.dumps(bwk_core.adopt_existing(account or "main"))
        if action == "connect":
            # Secrets never cross the model boundary: env-provided password only.
            if not (account or store.default_name()):
                return json.dumps({"success": False,
                                   "error": "no accounts; add one first (action=add)"})
            if not bwk_core.in_process_token():
                return json.dumps({
                    "success": False,
                    "error": "not signed in. Passwords never pass through chat: run "
                             "`hermes bitwarden-keeper connect " + (account or store.default_name() or "")
                             + "` in a terminal and type the master password there. The session "
                               "then persists until you disconnect it."})
            return json.dumps({"success": True, "account": account or store.default_name(),
                               "message": "already connected"})
        if action == "disconnect":
            return json.dumps(bwk_core.disconnect(account, logout=bool(params.get("logout"))))
        if action == "logout":
            return json.dumps(bwk_core.disconnect(account, logout=True))
        return json.dumps({"success": False, "error": f"unknown action {action!r}"})
    except Exception as exc:
        return json.dumps({"success": False, "error": str(exc)[:250]})


def _cli_setup(sub) -> None:
    sub.add_parser("status", help="list keeper accounts and their session state")
    p_add = sub.add_parser("add", help="register a new Bitwarden account")
    p_add.add_argument("name")
    p_add.add_argument("--server-url", default=None, help="self-hosted server URL")
    p_add.add_argument("--appdata-dir", default=None, help="custom bw appdata dir")
    p_rm = sub.add_parser("remove", help="remove an account (deletes its stored session)")
    p_rm.add_argument("name")
    p_use = sub.add_parser("use", help="set the default account")
    p_use.add_argument("name")
    p_ad = sub.add_parser("adopt", help="adopt the machine's existing bw appdata as an account")
    p_ad.add_argument("name", nargs="?", default="main")
    p_co = sub.add_parser("connect", help="sign in (type the master password; persists until disconnect)")
    p_co.add_argument("name", nargs="?")
    p_di = sub.add_parser("disconnect", help="forget the stored session (stays signed OUT until reconnect)")
    p_di.add_argument("name", nargs="?")
    p_di.add_argument("--logout", action="store_true", help="also `bw logout` that appdata")
    p_lo = sub.add_parser("logout", help="disconnect AND `bw logout`")
    p_lo.add_argument("name", nargs="?")


def _cli_handler(args) -> None:
    import getpass
    import sys

    import bwk_core

    action = getattr(args, "bwk_action", None) or args.__class__.__name__
    store = bwk_core.AccountStore()
    name = getattr(args, "name", None)
    try:
        if args.command == "status" or (not hasattr(args, "command")):
            print(json.dumps({"default": store.default_name(),
                              "accounts": store.status()}, indent=2))
        elif args.command == "add":
            print(json.dumps({"handle": store.add(name, appdata_dir=getattr(args, "appdata_dir", None),
                                                  server_url=getattr(args, "server_url", None))}))
            print(f"next: hermes bitwarden-keeper connect {name}")
        elif args.command == "remove":
            store.remove(name)
            print(f"removed {name}")
        elif args.command == "use":
            store.set_default(name)
            print(f"default account: {store.default_name()}")
        elif args.command == "adopt":
            out = bwk_core.adopt_existing(name or "main")
            print(json.dumps(out, indent=2))
        elif args.command in ("connect", "disconnect", "logout"):
            if args.command == "connect":
                result = bwk_core.connect(name, master_password=None, interactive=True)
            else:
                result = bwk_core.disconnect(name, logout=True)
            print(json.dumps(result, indent=2))
            if not result.get("success"):
                sys.exit(1)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


def register(ctx) -> None:
    # 1. Vault backend (best-effort: core refuses the seam for local installs).
    try:
        from bwk_backend import KeeperLoginBackend
        ctx.register_login_backend(KeeperLoginBackend())
        logger.info("bitwarden-keeper: login backend registered")
    except Exception as exc:
        logger.warning("bitwarden-keeper: login backend not registered (%s). "
                       "Use the bitwarden-keeper tool and CLI instead; browser_vault "
                       "fills keep using the core bitwarden backend.", str(exc)[:200])

    # 2. Model-facing tool (no secrets ever cross the model boundary).
    try:
        ctx.register_tool(name=TOOL_NAME, toolset=TOOL_NAME, schema=_SCHEMA,
                          handler=_tool_handler, description="Bitwarden Keeper account management")
    except Exception as exc:
        logger.warning("bitwarden-keeper: tool registration failed: %s", exc)

    # 3. CLI subcommand.
    try:
        def _setup(sub):
            sub.set_defaults(bwk_command="status")
            for name, help_text, builder in (
                ("status", "list accounts and session state", None),
                ("add", "register a new Bitwarden account", _cli_setup),
                ("remove", "remove an account", None),
                ("use", "set the default account", None),
                ("adopt", "adopt the machine's existing bw appdata", None),
                ("connect", "sign in from the terminal (persists until disconnect)", None),
                ("disconnect", "forget the stored session", None),
                ("logout", "disconnect and `bw logout`", None),
            ):
                p = sub.add_parser(name, help=help_text)
                if name == "add":
                    p.add_argument("name")
                    p.add_argument("--server-url", default=None)
                    p.add_argument("--appdata-dir", default=None)
                elif name in ("remove", "use"):
                    p.add_argument("name")
                elif name in ("adopt", "connect", "disconnect", "logout"):
                    p.add_argument("name", nargs="?")
                    if name == "disconnect":
                        p.add_argument("--logout", action="store_true")
                p.set_defaults(bwk_command=name)

        ctx.register_cli_command("bitwarden-keeper",
                                 help="multi-account Bitwarden sessions (persistent sign-in)",
                                 setup_fn=_setup,
                                 handler_fn=_cli_handler,
                                 description="Bitwarden Keeper account management")
    except Exception as exc:
        logger.warning("bitwarden-keeper: CLI registration failed: %s", exc)
