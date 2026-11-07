"""Account store + session lifecycle tests (fake bw, temp HERMES_HOME)."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

HERMES_SRC = os.environ.get("HERMES_SRC")
if HERMES_SRC and HERMES_SRC not in sys.path:
    sys.path.insert(0, HERMES_SRC)

PLUGIN_DIR = Path(__file__).resolve().parent.parent
for p in (PLUGIN_DIR,):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import bwk_core  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    fake_bw = PLUGIN_DIR / "tests" / "fakebw.py"
    os.chmod(fake_bw, 0o755)
    cfg = {"binary_path": str(fake_bw)}
    store = bwk_core.AccountStore(home=tmp_path)
    return store, cfg, tmp_path


def test_add_list_default_remove(env):
    store, cfg, home = env
    h1 = store.add("personal")
    h2 = store.add("work", server_url="https://vault.example.com")
    assert h1 == "bwk:personal" and h2 == "bwk:work"
    assert store.names() == ["personal", "work"]
    assert store.default_name() == "personal"  # first account becomes default
    store.set_default("work")
    assert store.default_name() == "work"
    store.remove("work")
    assert store.default_name() == "personal"  # default re-assigned
    assert store.names() == ["personal"]
    with pytest.raises(ValueError):
        store.add("personal")
    # metadata file lives under HERMES_HOME, not Path.home()
    assert store.accounts_file == home / "bitwarden-keeper" / "accounts.json"


def test_connect_mints_persists_and_is_0600(env, monkeypatch):
    store, cfg, home = env
    store.add("personal")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "correct horse battery staple")
    out = bwk_core.connect("personal", cfg=cfg)
    assert out["success"] is True and out["minted"] is True

    sess = store.session_file("personal")
    marker = store.persist_marker("personal")
    assert sess.is_file() and marker.is_file()
    assert (sess.stat().st_mode & 0o777) == 0o600
    token = sess.read_text().strip()
    assert token.startswith("tok-")
    # in-process store holds it and it validates
    assert bwk_core.in_process_token() == token
    assert bwk_core.session_valid("personal", token, cfg)

    # reconnect reuses the valid session — no new mint
    out2 = bwk_core.connect("personal", cfg=cfg)
    assert out2["success"] is True and out2["minted"] is False
    assert store.read_session_file("personal") == token


def test_restore_across_fresh_instance_gated_by_marker(env, monkeypatch):
    store, cfg, home = env
    store.add("personal")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "pw1")
    bwk_core.connect("personal", cfg=cfg)
    token = store.read_session_file("personal")

    # simulate a restart: drop the in-process token
    bwk_core.in_process_lock()

    # marker present -> restore works
    fresh = bwk_core.AccountStore(home=home)
    assert fresh.persist_marker("personal").is_file()
    assert bwk_core.restore_if_allowed("personal", cfg) is True
    assert bwk_core.in_process_token() == token

    # no marker -> restore refused even with the session file present
    bwk_core.in_process_lock()
    fresh.persist_marker("personal").unlink()
    assert bwk_core.restore_if_allowed("personal", cfg) is False
    assert bwk_core.in_process_token() is None


def test_disconnect_deletes_and_fences_inflight_commit(env, monkeypatch):
    store, cfg, home = env
    store.add("personal")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "pw2")
    bwk_core.connect("personal", cfg=cfg)
    stale_generation = bwk_core.in_process_begin()

    out = bwk_core.disconnect("personal")
    assert out["success"] is True
    assert not store.session_file("personal").is_file()
    assert not store.persist_marker("personal").is_file()
    assert bwk_core.in_process_token() is None
    # an unlock that began before the lock must NOT commit afterwards (fence)
    assert bwk_core.in_process_store_token("tok-aaaaaaaa", stale_generation) is False

    # session_valid now fails (no token)
    assert bwk_core.session_valid("personal", None, cfg) is False


def test_logout_runs_in_account_appdata(env, monkeypatch):
    store, cfg, home = env
    store.add("personal")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "pw3")
    bwk_core.connect("personal", cfg=cfg)
    appdata = store.appdata_dir("personal")
    out = bwk_core.disconnect("personal", logout=True, cfg=cfg)
    assert out["success"] and out.get("logged_out") is True
    assert (appdata / "logged_out").is_file()


def test_bad_names_and_missing_account(env):
    store, cfg, home = env
    with pytest.raises(ValueError):
        store.add("Bad Name!")
    with pytest.raises(ValueError):
        store.require("nope")
    with pytest.raises(ValueError):
        bwk_core.connect(cfg=cfg)  # no accounts at all


def test_handle_splitting():
    assert bwk_core.split_handle("bwk:personal") == ("personal", None)
    assert bwk_core.split_handle("bwk:personal:1111-2222") == ("personal", "1111-2222")
    assert bwk_core.split_handle("bw:other") == ("bw:other", None)


def test_secrets_never_in_argv_or_accounts_json(env, monkeypatch):
    store, cfg, home = env
    store.add("personal")
    monkeypatch.setenv("HERMES_BW_KEEPER_MASTER", "sekrit-passwd-xyz")
    bwk_core.connect("personal", cfg=cfg)
    meta = json.loads(store.accounts_file.read_text())
    assert "sekrit-passwd-xyz" not in store.accounts_file.read_text()
    assert not any("sekrit" in str(v) for v in meta["personal"].values())
    # the session file itself is the only place the token lives
    assert meta["personal"].keys() == {"appdata_dir", "server_url", "default"}
