# bitwarden-keeper

Persistent **multi-account** Bitwarden for Hermes Agent: sign in once from a
terminal and the session stays until you explicitly disconnect it — across
gateway restarts, profile switches and reboots of the machine.

## What you get

- **Sign in once, stays signed in** — connect writes the account's `BW_SESSION`
  token to a `0600` file and a credential-free "persist" marker. On restart the
  plugin restores and re-validates the session; nothing idles it out.
- **Multiple accounts** — each account gets its own bw appdata dir
  (`BITWARDENCLI_APPDATA_DIR`), so two or more accounts hold simultaneous,
  independent sessions. Handles are namespaced: `bwk:<account>` /
  `bwk:<account>:<item-id>`.
- **Built-in desktop UI** — a configuration pane (account state, default
  account, two-step disconnect) and a statusbar lock chip.
- **Model-safe** — master passwords and session tokens never cross the model
  boundary, argv, or the dashboard. Sign-in happens in your terminal
  (`getpass`); tool results report metadata only, and resolved passwords are
  registered with Hermes' model-egress redaction.

## Requirements

- Hermes (no core patch needed — the plugin uses existing seams only)
- `bw` CLI ≥ 1.x (per-account isolation uses `BITWARDENCLI_APPDATA_DIR`)
- For `bwk:` browser_vault fills: see "Vault backend admission" below.

## Install

```bash
mkdir -p ~/.hermes/plugins/bitwarden-keeper
tar -xzf bitwarden-keeper-0.1.1.tar.gz -C ~/.hermes/plugins/
```

Add to `config.yaml`:

```yaml
plugins:
  enabled:
    - bitwarden-keeper
```

## Use

```bash
hermes bitwarden-keeper add personal            # register an account
hermes bitwarden-keeper add work --server-url https://vault.example.com
hermes bitwarden-keeper adopt                   # adopt the machine's existing bw appdata
hermes bitwarden-keeper connect personal        # sign in (type the master password there)
hermes bitwarden-keeper status                  # what's connected / persisted
hermes bitwarden-keeper use work                # set the default account
hermes bitwarden-keeper disconnect personal     # forget the stored session
hermes bitwarden-keeper logout personal         # disconnect AND `bw logout`
```

Connect is the only step that ever touches a master password — it is read by
`getpass` in your terminal or taken from the `HERMES_BW_KEEPER_MASTER`
environment variable, and passed to `bw unlock --passwordenv` (never argv).

## How state is stored

| Path | Perms | Contents |
|---|---|---|
| `~/.hermes/bitwarden-keeper/accounts.json` | 0600 | account metadata (no secrets) |
| `~/.hermes/secrets/bitwarden-keeper/<acct>.session` | 0600 | the account's `BW_SESSION` token |
| `~/.hermes/secrets/bitwarden-keeper/<acct>.persist` | 0600 | permission marker (no credentials) |
| `~/.hermes/bitwarden-keeper/<acct>/appdata/` | 0700 | bw's own per-account appdata |

Restore only happens when the persist marker exists. Disconnect (or an
explicit lock) deletes marker + session file and bumps a lock generation so an
in-flight unlock cannot re-commit over it — the same fencing the core vault
store uses.

## Vault backend admission (honest limitation)

The plugin registers a `bwk:` LoginBackend so `browser_vault` fills work
against every connected account. **Core only admits login-backend registration
from bundled or catalog-installed plugins** (provenance gate,
`vault.<name>.enabled: true` also required). On a plain local install the
registration is refused by design; the plugin degrades to tool + CLI access
and browser fills keep using the core `bitwarden` backend. Feeding this plugin
through the official catalog (or bundling it) enables the seam — no code
change needed.

## Desktop UI

The pane and chip are the `desktop/plugin.js` half of this package — the
desktop app loads it from `plugins/<id>/desktop/` and it appears under
Settings → Plugins (toggle it on there; the Python half is gated separately by
`plugins.enabled`). The pane is deliberately read-only: connect/disconnect are
terminal actions, and the pane shows the exact command to run.

## Test

```bash
HERMES_SRC=/path/to/hermes-agent ./run_tests.sh
```

Runs against a **fake `bw` shim** and a disposable `HERMES_HOME` — real vault
state is never touched. Covers: account CRUD, connect/persist/restore-gating,
disconnect fencing, backend handles/fills/redaction, subprocess env isolation,
and multi-account appdata separation.

## License

MIT — Copyright (c) 2026 Jacob Hodge.
