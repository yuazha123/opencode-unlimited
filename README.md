# Opencode Unlimited

A small, dependency-free Python toolkit for managing the network identity used
by the OpenCode client, recovering from quota walls, and running an
authenticated egress relay.

Everything runs from the command line. Nothing is installed automatically: no
services, no scheduled tasks, no sudoers rules, no firewall changes, and no
remote scripts. Python 3.11+ and the standard library are the only requirements.

> Check the terms of service of any third-party platform before using this
> tool. You are responsible for how you use it.

## Features

- **Local CONNECT proxy** (`ouc lane`) with a bounded health-event trail, live
  tunnel counting, TCP keepalive, and clear classification of stream resets.
- **Egress modes** — `warp`, `tor`, `custom`, and `clean` — with proxy strings
  in `socks5://`, `http://`, `relay://`, and `relayplain://` form.
- **Block relay** (`relay/blockrelay.py`) — a blind, token-authenticated CONNECT
  tunnel that assigns each client a sticky IPv6 `/64`, with prefix, WarpGate,
  and hybrid lanes. It never terminates TLS or modifies requests.
- **Quota-wall watcher** (`ouc guard`) — detects wall messages in the client
  log, holds rotation while a response is streaming, applies a cooldown, and
  pauses until 00:00 UTC after two confirmed egress changes still hit a wall.
- **Loopback dashboard** (`ouc dashboard`) — a JSON API and single-page UI for
  the same controls. No WebView dependency, no remote binding.
- **Optional archive editor** (`ouc desktop-brand`) — dry-run by default;
  updates specific strings in an Electron `app.asar` with atomic swap,
  read-back verification, and byte-exact restore.
- **Opt-in resume helper** — disabled until enabled with `ouc resume --enable on`.

## Install

```sh
git clone https://github.com/yuazha123/opencode-unlimited.git
cd opencode-unlimited
python -m unittest discover -s tests -v
```

There is no `pip install` step. Run modules with `python -m ouc.cli`.

## CLI

```sh
python -m ouc.cli doctor                 # local health snapshot (JSON)
python -m ouc.cli config show            # current egress configuration
python -m ouc.cli config set --mode custom --proxy socks5://127.0.0.1:10808
python -m ouc.cli hop                    # show the next egress entry
python -m ouc.cli hop --commit           # advance the proxy ring
python -m ouc.cli lane --port 41987      # run the loopback CONNECT proxy
python -m ouc.cli guard                  # one wall-detection tick
python -m ouc.cli keeper                 # one keeper tick
python -m ouc.cli watchdog --worker guard
python -m ouc.cli dashboard --port 42914 # serve the dashboard
python -m ouc.cli desktop-brand status --install "/path/to/OpenCode"
python -m ouc.cli desktop-brand apply --install "/path/to/OpenCode" --apply
python -m ouc.cli desktop-brand restore --install "/path/to/OpenCode"
python -m ouc.cli resume --enable on
```

`echo "relay://block:TOKEN@relay.example.com:4443" | python -m ouc.cli parse-proxy`
parses a relay entry.

## State

All state is kept under a per-user data directory:

| Platform | Root |
|---|---|
| Windows | `%LOCALAPPDATA%\opencode-unlimited` |
| Linux/macOS | `$XDG_DATA_HOME/opencode-unlimited` (default `~/.local/share`) |

Subdirectories: `guard`, `keeper`, `lane`, `desktop`, `scripts`, `bin`.
JSON writes are atomic (temporary file plus rename). Logs have a one-backup
size rotation.

Environment overrides:

| Variable | Effect |
|---|---|
| `OUC_SERVICE_PROXY_PORT` | Service proxy port used by health checks (default `41987`) |
| `OUC_RELAY_INSECURE` | Set to `1` to disable relay certificate verification (explicit opt-in) |

## Relay

Copy `relay/config.example.json`, replace every `CHANGE-ME-*` placeholder, and
choose a lane:

```json
"upstream": { "mode": "prefix" }
```

- `prefix` — bind outbound sockets to addresses in the routed IPv6 prefix
  (Linux `IP_FREEBIND`). Requires `prefixes`.
- `warpgate` — dial through WarpGate SOCKS5 instances. Requires
  `upstream.warpgate.url`.
- `hybrid` — prefix first, WarpGate when the prefix has nothing left.

The default listener is `127.0.0.1:4443`. A non-loopback listener requires a
TLS certificate and key in the config.

```sh
python -m relay.blockrelay doctor  -c relay/config.json
python -m relay.blockrelay client-new -c relay/config.json --label laptop
python -m relay.blockrelay client-list -c relay/config.json
python -m relay.blockrelay client-rotate -c relay/config.json --id cl_...
python -m relay.blockrelay client-revoke -c relay/config.json --id cl_...
python -m relay.blockrelay serve -c relay/config.json
```

Client tokens are generated with `secrets.token_urlsafe(32)` and stored only as
SHA-256 hashes. Admin and enrollment tokens are compared with
`secrets.compare_digest`. The control API exposes `/api/enroll`, `/api/state`,
and `/api/rotate`. No token is printed except by `client-new`, and no secret is
stored in this repository.

## Layout

```
ouc/
  common.py         paths, JSON/IO helpers, egress probing, UTC helpers
  proxy_chain.py    egress config, proxy parsing, relay client, upstream dialing
  zen_proxy.py      threaded CONNECT proxy and health-event trail
  workers.py        wall detection, rotation backoff, heartbeats
  auto_resume.py    opt-in lockout clearing and session resume dispatch
  desktop_brand.py  dry-run asar string editor with byte-exact restore
  dashboard.py      loopback HTTP dashboard and JSON API
  cli.py            unified command line
relay/
  blockrelay.py     token-authenticated CONNECT relay and control API
  warpgate_pool.py  WarpGate control-plane client and SOCKS5 dialer
tests/              standard-library unit tests (no network, no subprocesses)
```

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests inject sockets, HTTP openers, clocks, runners, and filesystem paths.
They never contact a live service, spawn a process, or modify a real
application archive.

## License

MIT. See [LICENSE](LICENSE).
