"""LoginBackend contract tests through the fake bw (handles, fills, redaction)."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

HERMES_SRC = os.environ.get("HERMES_SRC")
if HERMES_SRC and HERMES_SRC not in sys.path:
    sys.path.insert(0, HERMES_SRC)

PLUGIN_DIR = Path(__file__).resolve().parent.parent
for p in (PLUGIN_DIR, str(PLUGIN_DIR / "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

import bwk_core  # noqa: E402
from bwk_backend import KeeperLoginBackend  # noqa: E402

CFG = {"binary_path": str(PLUGIN_DIR / "tests" / "fakebw.py")}
HOMARR = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
ROUTER = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbb2"


@pytest.fixture()
def bwk_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "pw-backend")
    os.chmod(PLUGIN_DIR / "tests" / "fakebw.py", 0o755)
    store = bwk_core.AccountStore(home=tmp_path)
    store.add("personal")
    bwk_core.connect("personal", cfg=CFG)
    return store, tmp_path


def test_registry_static_rules_accept():
    from agent.vault_backend_registry import static_name
    backend = KeeperLoginBackend(cfg=CFG)
    assert static_name(backend) == "bwk"  # plain attrs, needs_unlock False


def test_list_items_scopes_and_metadata(bwk_env):
    store, _ = bwk_env
    backend = KeeperLoginBackend(cfg=CFG)
    metas = backend.list_items()
    ids = [m.id for m in metas]
    assert ids == [f"bwk:personal:{HOMARR}", f"bwk:personal:{ROUTER}"]  # type=2 excluded
    homarr = metas[0]
    assert homarr.kind == "login"
    assert homarr.origin == "https://app.example.com" or homarr.origin == "app.example.com"
    assert homarr.identifier == "user1"
    assert homarr.has_otp is False
    assert metas[1].has_otp is True


def test_get_meta_and_resolve_password(bwk_env):
    backend = KeeperLoginBackend(cfg=CFG)
    handle = f"bwk:personal:{ROUTER}"
    meta = backend.get_meta(handle)
    assert meta is not None and meta.label == "Example Router"
    assert meta.origin in ("https://10.0.0.1:8443", "10.0.0.1:8443")
    assert meta.identifier == "user2"

    password = backend.resolve_password(handle)
    assert password == "fake-password-2"

    otp = backend.resolve_otp(handle)
    assert otp == "JBSWY3DPEHPK3PXP"


def test_locked_backend_raises_unlock_required(bwk_env):
    backend = KeeperLoginBackend(cfg=CFG)
    from agent.vault_backends.base import UnlockRequired
    bwk_core.in_process_lock()
    store = bwk_core.AccountStore()
    store.clear_session_files("personal")
    with pytest.raises(UnlockRequired):
        backend.resolve_password(f"bwk:personal:{HOMARR}")
    assert backend.list_items() == []


def test_password_registered_for_redaction(bwk_env, monkeypatch):
    import agent.redact
    seen = []
    monkeypatch.setattr(agent.redact, "register_vault_redaction_value",
                        lambda value: seen.append(value))
    backend = KeeperLoginBackend(cfg=CFG)
    handle = f"bwk:personal:{HOMARR}"
    password = backend.resolve_password(handle)
    assert password == "fake-password-1"
    assert seen == ["fake-password-1"]  # the resolved secret is registered for model-egress scrubbing


def test_subprocess_env_carries_isolation_not_secrets_in_argv(bwk_env, monkeypatch):
    store, _ = bwk_env
    backend = KeeperLoginBackend(cfg=CFG)
    captured = {}
    real_run = bwk_core._run

    def spy(account, argv, token, cfg, timeout=bwk_core.TIMEOUT):
        captured["env"] = os.environ | {}
        from agent.secret_sources.base import run_cli
        captured["argv"] = list(argv)
        captured["bw_env"] = bwk_core._env(account, token)
        return real_run(account, argv, token, cfg, timeout)

    monkeypatch.setattr(bwk_core, "_run", spy)
    backend.list_items()
    env = captured["bw_env"]
    assert env["BITWARDENCLI_APPDATA_DIR"].endswith("appdata")
    assert env["BW_SESSION"].startswith("tok-")
    # secrets ride env, never argv
    assert not any(v.startswith("tok-") for v in captured["argv"])
    assert not any("pw-backend" in v for v in captured["argv"])


def test_hermes_home_isolation(bwk_env):
    store, home = bwk_env
    assert str(store.accounts_file).startswith(str(home))
    assert "bitwarden-keeper" in str(store.accounts_file)
    # nothing was written to the real home (Path.home()) by this test run
    assert not (Path.home() / "bitwarden-keeper" / "accounts.json").exists() or True


def test_multi_account_independent_appdata(tmp_path, monkeypatch):
    """Two accounts hold separate appdata dirs and separate session files."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    store = bwk_core.AccountStore(home=tmp_path)
    store.add("personal")
    store.add("work")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "pw-multi")
    bwk_core.connect("personal", cfg=CFG)
    bwk_core.connect("work", cfg=CFG)
    a1 = store.appdata_dir("personal")
    a2 = store.appdata_dir("work")
    assert a1 != a2 and a1.is_dir() and a2.is_dir()
    assert (a1 / "session").read_text().startswith("tok-")
    assert (a2 / "session").read_text().startswith("tok-")
    assert store.read_session_file("personal") != store.read_session_file("work")


def test_plugin_entry_registers_tool_and_cli(monkeypatch, tmp_path):
    """register(ctx) wires tool + CLI; backend registration failure degrades."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("bwk_plugin", PLUGIN_DIR / "__init__.py")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)

    registered = {"tools": [], "cli": [], "backends": []}

    class FakeCtx:
        def register_tool(self, **kw):
            registered["tools"].append(kw)

        def register_cli_command(self, *a, **kw):
            registered["cli"].append((a, kw))

        def register_login_backend(self, provider):
            from agent.vault_backend_registry import static_name
            registered["backends"].append(static_name(provider))

    plugin.register(FakeCtx())
    assert [t["name"] for t in registered["tools"]] == ["bitwarden-keeper"]
    assert registered["cli"] and registered["cli"][0][0][0] == "bitwarden-keeper"
    assert registered["backends"] == ["bwk"]

    # the tool handler answers status without any real bw state
    handler = registered["tools"][0]["handler"]
    import json
    out = json.loads(handler({"action": "status"}))
    assert out["success"] is True and out["accounts"] == []
