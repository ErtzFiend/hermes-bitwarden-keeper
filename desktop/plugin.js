/**
 * bitwarden-keeper — desktop configuration pane + statusbar lock chip.
 *
 * Read-only surface by design: connect/disconnect are deliberate user actions
 * in the terminal (passwords never cross the UI or the model). The pane shows
 * every account's state (connected / persisted / default), a "Set default"
 * button, a two-click Disconnect, and copyable connect instructions.
 *
 * Data comes from this plugin's own dashboard backend (dashboard/plugin_api.py
 * served at /api/plugins/bitwarden-keeper). Polling is slow (30s) — states
 * only change when the user acts.
 */
import { host, useValue } from '@hermes/plugin-sdk'
import { jsx, Fragment } from 'react/jsx-runtime'
import { useEffect, useState } from 'react'

const POLL_MS = 30000

const card = {
  border: '1px solid var(--ui-stroke-secondary)',
  borderRadius: 8,
  padding: '10px 12px',
  display: 'flex',
  flexDirection: 'column',
  gap: 6
}
const row = { display: 'flex', alignItems: 'center', gap: 8 }
const dim = { color: 'var(--ui-text-tertiary)', fontSize: 12 }
const btn = {
  border: '1px solid var(--ui-stroke-secondary)',
  borderRadius: 6,
  background: 'transparent',
  color: 'var(--ui-text-secondary)',
  fontSize: 12,
  padding: '3px 10px',
  cursor: 'pointer'
}

function Badge({ children, tone }) {
  const color = tone === 'ok' ? 'var(--ui-accent)' : tone === 'warn' ? 'var(--ui-text-tertiary)' : 'var(--ui-text-quaternary)'
  return jsx('span', {
    style: { color, border: `1px solid ${color}`, borderRadius: 999, fontSize: 11, padding: '1px 8px' },
    children
  })
}

function AccountCard({ acct, onRefresh, ctx }) {
  const [confirming, setConfirming] = useState(false)
  const connected = !!acct.valid || !!acct.session_file
  const dot = connected ? 'var(--ui-accent)' : 'var(--ui-text-quaternary)'
  const copyConnect = async () => {
    const cmd = `hermes bitwarden-keeper connect ${acct.name}`
    await ctx.os.writeClipboard(cmd)
    host.notify({ kind: 'info', message: `Copied: ${cmd} — run it in a terminal to sign in` })
  }
  const doDisconnect = () => {
    if (!confirming) { setConfirming(true); return }
    setConfirming(false)
    host.notify({ kind: 'warning', message: `Run \`hermes bitwarden-keeper disconnect ${acct.name}\` in a terminal to disconnect (two-step on purpose).` })
  }
  const setDefault = () => {
    host.notify({ kind: 'info', message: `Run \`hermes bitwarden-keeper use ${acct.name}\` in a terminal.` })
  }
  return jsx('div', { style: card, children: [
    jsx('div', { key: 'h', style: row, children: [
      jsx('span', { key: 'dot', style: { width: 8, height: 8, borderRadius: 999, background: dot }, 'aria-hidden': 'true' }),
      jsx('span', { key: 'n', style: { fontWeight: 600 }, children: acct.name }),
      acct.default ? jsx(Badge, { key: 'd', tone: 'ok', children: 'default' }) : null,
      connected ? jsx(Badge, { key: 'c', tone: 'ok', children: 'connected' }) : jsx(Badge, { key: 'c', tone: 'off', children: 'disconnected' }),
      acct.persist_marker ? jsx(Badge, { key: 'p', tone: 'warn', children: 'persists' }) : null
    ]}),
    jsx('div', { key: 's', style: dim, children: `${acct.server_url} · ${connected ? 'session stored (0600)' : 'no stored session'}` }),
    jsx('div', { key: 'b', style: { ...row, flexWrap: 'wrap' }, children: [
      !acct.default ? jsx('button', { key: 'def', style: btn, onClick: setDefault, children: 'Set default' }) : null,
      connected ? jsx('button', { key: 'disc', style: { ...btn, color: confirming ? 'var(--ui-accent)' : undefined }, onClick: doDisconnect, children: confirming ? 'Confirm disconnect?' : 'Disconnect' }) : jsx('button', { key: 'conn', style: btn, onClick: copyConnect, children: 'Copy connect command' })
    ]})
  ]})
}

function Pane({ ctx }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const payload = await ctx.rest('/status')
        if (alive) { setData(payload); setErr(null) }
      } catch (e) {
        if (alive) setErr(String((e && e.message) || e))
      }
    }
    void load()
    const off = ctx.setInterval(load, POLL_MS)
    return () => { alive = false; off() }
  }, [ctx])

  return jsx('div', { style: { padding: 12, display: 'flex', flexDirection: 'column', gap: 10, height: '100%', overflowY: 'auto' }, children: [
    jsx('div', { key: 't', children: [
      jsx('div', { style: { fontWeight: 700 }, children: 'Bitwarden Keeper' }),
      jsx('div', { style: dim, children: 'Sign in once from a terminal; the session persists until you disconnect it.' })
    ]}),
    err ? jsx('div', { key: 'e', style: { ...dim, color: 'var(--ui-text-secondary)' }, children: `backend unreachable: ${err}` }) : null,
    data && Array.isArray(data.accounts) && data.accounts.length
      ? data.accounts.map((a) => jsx(AccountCard, { key: a.name, acct: a, ctx }))
      : jsx('div', { key: 'empty', style: dim, children: data && data.ok ? 'No keeper accounts yet — run `hermes bitwarden-keeper add <name>` in a terminal.' : 'Waiting for backend…' })
  ]})
}

function Chip({ ctx }) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const payload = await ctx.rest('/status')
        if (alive) setData(payload)
      } catch (_) { /* chip stays dim */ }
    }
    void load()
    const off = ctx.setInterval(load, POLL_MS)
    return () => { alive = false; off() }
  }, [ctx])
  const accounts = (data && Array.isArray(data.accounts)) ? data.accounts : []
  const def = accounts.find((a) => a.default) || null
  const connected = def ? (!!def.session_file) : false
  const tone = connected ? 'var(--ui-accent)' : 'var(--ui-text-quaternary)'
  const title = def
    ? `Bitwarden Keeper: ${def.name} ${connected ? 'connected' : 'disconnected'} (${accounts.length} account${accounts.length === 1 ? '' : 's'})`
    : 'Bitwarden Keeper: no accounts'
  return jsx('button', {
    type: 'button',
    title,
    className: 'px-1.5 text-[0.6875rem]',
    style: { color: tone },
    children: [
      jsx('span', { key: 'k', children: 'BW' }),
      jsx('span', { key: 'd', 'aria-hidden': 'true', style: { marginLeft: 4 }, children: connected ? '●' : '○' })
    ]
  })
}

export default {
  id: 'bitwarden-keeper',
  name: 'Bitwarden Keeper',
  description: 'Persistent multi-account Bitwarden sessions: config pane + lock-state chip.',
  defaultEnabled: true,
  register(ctx) {
    ctx.register({
      id: 'accounts',
      area: 'panes',
      title: 'Bitwarden Keeper',
      data: { placement: 'right', width: 300 },
      render: () => jsx(Pane, { ctx })
    })
    ctx.register({
      id: 'chip',
      area: 'statusBar.right',
      order: 117,
      render: () => jsx(Chip, { ctx })
    })
  }
}
