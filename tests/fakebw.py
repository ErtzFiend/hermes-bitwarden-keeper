#!/usr/bin/env python3
"""A hermetic fake `bw` CLI for tests. Never touches a real vault.

Emulates exactly the surface bitwarden-keeper uses:

    bw unlock --raw --nointeraction --passwordenv HERMES_BW_KEEPER_MASTER
    bw list items [--search <term>]
    bw get item <id> | password <id> | totp <id>
    bw logout

State lives in BITWARDENCLI_APPDATA_DIR: a session is a token file named
`session` written at unlock; `logout` touches `logged_out`. Item fixtures are
read from `items.json` placed NEXT TO the shim script by the tests.
"""

import json
import os
import sys
from pathlib import Path


def appdata() -> Path:
    return Path(os.environ.get("BITWARDENCLI_APPDATA_DIR") or ".")


def unlocked() -> bool:
    tok = os.environ.get("BW_SESSION", "")
    return tok.startswith("tok-") and (appdata() / "session").exists()


def items() -> list:
    fixture = Path(__file__).resolve().parent / "fakebw_items.json"
    try:
        data = json.loads(fixture.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def main(argv):
    if not argv:
        print("fake bw: no command", file=sys.stderr)
        return 1
    cmd = argv[0]

    if cmd == "unlock":
        password = os.environ.get("HERMES_BW_KEEPER_MASTER", "")
        if not password:
            print("Master password is required", file=sys.stderr)
            return 1
        ad = appdata()
        ad.mkdir(parents=True, exist_ok=True)
        token = "tok-" + os.urandom(8).hex()
        (ad / "session").write_text(token)
        print(token)
        return 0

    if cmd == "logout":
        ad = appdata()
        (ad / "logged_out").touch()
        (ad / "session").unlink(missing_ok=True)
        return 0

    if not unlocked():
        print("Vault is locked.", file=sys.stderr)
        return 1

    if cmd == "list" and len(argv) > 1 and argv[1] == "items":
        if "--search" in argv:
            # Probe searches must return a well-formed empty list when unlocked.
            print("[]")
            return 0
        print(json.dumps(items()))
        return 0

    if cmd == "get" and len(argv) >= 3:
        what, item_id = argv[1], argv[2]
        for item in items():
            if item.get("id") == item_id:
                if what == "item":
                    print(json.dumps(item))
                    return 0
                login = item.get("login") or {}
                if what == "password":
                    value = login.get("password")
                    if not value:
                        print("Password is empty", file=sys.stderr)
                        return 1
                    print(value)
                    return 0
                if what == "totp":
                    totp = login.get("totp")
                    if not totp:
                        print("No TOTP", file=sys.stderr)
                        return 1
                    print(totp)
                    return 0
        print(f"Not found: {item_id}", file=sys.stderr)
        return 1

    print(f"fake bw: unsupported command {argv}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
