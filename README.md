# strfry-ratelimit

A [strfry](https://github.com/hoytech/strfry) **writePolicy plugin** that (1) drops events of
configured kinds and (2) rate-limits writes per pubkey and (optionally) auto-bans abusers — without
patching strfry itself. It runs as a
separate process that strfry talks to over stdin/stdout, so it works with stock/upstream strfry.

## What it does

- **Kind blocklist.** Events whose `kind` matches `RL_BLOCK_KINDS` (individual kinds and/or
  inclusive ranges) are rejected outright, before rate limiting. This catches ephemeral floods
  (e.g. relayed WebRTC signaling) that per-pubkey rate limiting can't stop because each event
  uses a throwaway pubkey.
- **Per-pubkey sliding-window rate limit.** Up to `RL_MAX_EVENTS` accepted per `RL_WINDOW_SECONDS`
  per pubkey. A longer window separates one-time bursts (fixed count) from sustained spam (which
  scales with the window), so a generous window tolerates legit bursts while still catching floods.
- **Kind-class aware.** Only *accumulating* kinds are limited:
  - **Ephemeral** (20000–29999): never stored → exempt by default.
  - **Replaceable** (0, 3, 41, 10000–19999): only the latest per (pubkey,kind) is stored → exempt.
  - **Regular** + **Addressable** (30000–39999): can accumulate → limited.
  - Plus an explicit `RL_EXCLUDE_KINDS` list (default `7` = reactions).
- **Relay-wide ephemeral ceiling.** An optional global token-bucket cap on ephemeral events
  (`RL_EPHEMERAL_RATE_PER_SEC`), for *distributed* floods that spread across many pubkeys so no
  per-sender limit can see them. Kind-agnostic, so it survives an attacker switching kinds.
  Off by default — [see below](#relay-wide-ephemeral-ceiling-distributed-flood-defence).
- **Optional auto-ban.** When `RL_BAN_ON_EXCEED=true`, a pubkey that exceeds the limit is banned
  (all its events rejected) and persisted to `RL_BAN_LIST_FILE`. Remove the line and restart to unban.

## Build

```sh
cargo build --release
# binary at target/release/strfry-ratelimit
```

## Configure strfry

`relay.writePolicy.plugin` must be a single command. Use a small wrapper to set env vars
(see `examples/ratelimit-wrapper.sh`):

```hocon
relay {
    writePolicy {
        plugin = "/path/to/strfry-ratelimit/examples/ratelimit-wrapper.sh"
    }
}
```

## Configuration (environment variables)

| Variable               | Default | Meaning |
|------------------------|---------|---------|
| `RL_CONFIG_FILE`       | (none)  | Load settings from this file instead of env vars; hot-reloaded on change (see below) |
| `RL_BLOCK_KINDS`        | (none)  | Kinds dropped outright, before rate limiting. Comma-separated singles and/or `lo-hi` ranges, e.g. `20001,22000-22999` |
| `RL_WINDOW_SECONDS`    | `60`    | Sliding window length (seconds) |
| `RL_MAX_EVENTS`        | `10`    | Max accepted events per window per pubkey |
| `RL_MODE`              | `reject`| `reject` (OK false) or `shadow` (OK true but dropped) |
| `RL_BAN_ON_EXCEED`     | `false` | Permanently ban a pubkey that exceeds the limit |
| `RL_BAN_LIST_FILE`     | (none)  | Path to persist bans (64-char hex, one per line) |
| `RL_EXCLUDE_KINDS`     | `7`     | Comma-separated kinds to never limit |
| `RL_EXEMPT_EPHEMERAL`  | `true`  | Exempt ephemeral kinds (20000–29999) |
| `RL_EXEMPT_REPLACEABLE`| `true`  | Exempt replaceable kinds (0,3,41,10000–19999) |
| `RL_EXEMPT_ADDRESSABLE`| `false` | Exempt addressable kinds (30000–39999) |
| `RL_EPHEMERAL_RATE_PER_SEC` | `0` (off) | Relay-wide ceiling on ephemeral events (20000–29999), events/second. See below |
| `RL_EPHEMERAL_BURST`   | auto    | Bucket depth for the ceiling — instantaneous burst allowed before the sustained rate applies. Unset/too small becomes `max(rate, 1)` (with a warning) |

Example tuned for a busy relay (≈100 spam events/min must be caught, legit bursts ≈30 must pass):

```sh
RL_WINDOW_SECONDS=180 RL_MAX_EVENTS=100 RL_BAN_ON_EXCEED=true \
RL_BAN_LIST_FILE=./strfry-db/banned-pubkeys.txt
```

### Relay-wide ephemeral ceiling (distributed-flood defence)

Per-pubkey limits cannot see a **distributed** flood: hundreds of pubkeys each
sending a modest rate sum to a firehose while every individual sender stays under
the limit. `RL_EPHEMERAL_RATE_PER_SEC` adds a single global token-bucket budget
for ephemeral kinds, which catches exactly that shape.

It is **kind-agnostic**, so unlike `RL_BLOCK_KINDS` it does not need to know
which kind is being abused and cannot be evaded by switching to another
ephemeral kind. (An attacker who leaves the ephemeral range entirely — e.g.
kind 1 — exits this ceiling and falls back on the per-pubkey limiter.)
Over-limit events get `shadowReject` (the sender sees OK, nothing is stored or
broadcast), so a flood source gets no signal to change tactics.

**What it does and does not protect.** This is a single first-come-first-served
budget with no per-sender fairness: during a flood, tokens are won roughly in
proportion to share of traffic, so a legitimate client sending 0.5% of the
ephemeral volume gets ~0.5% of the budget. It caps total relay load — the relay
stays up and non-ephemeral traffic (posts, reactions, DMs) is untouched — but it
does **not** keep ephemeral traffic working for legitimate users while a flood
is in progress; it degrades everyone's ephemeral traffic by volume share. Choose
it over `RL_BLOCK_KINDS` because it survives kind-switching and needs no
per-incident tuning, not because it shields individual users mid-flood.

Already-banned pubkeys are rejected before they can consume the budget.

Shed events still count against the per-pubkey window **only when
`RL_EXEMPT_EPHEMERAL=false`**; with the default `true`, ephemeral kinds sit
outside the per-pubkey limiter entirely, so `RL_BAN_ON_EXCEED` will **not** fire
on an ephemeral flood — the ceiling caps it, but no one gets banned for it.
If you do set `RL_EXEMPT_EPHEMERAL=false` alongside `RL_BAN_ON_EXCEED=true`, be
aware of the flip side: during a flood a bystander's shed events still burn
their own window, so a legitimate user can be auto-banned (across all kinds) for
traffic the relay never stored.

Scope: the budget is per plugin process. `strfry relay` runs one writer thread
and so one plugin instance, but `strfry stream`/`sync` each spawn their own, and
`strfry router` spawns **two per stream group** (up and down) — each with an
independent bucket.

Size it from your relay's actual ephemeral baseline, not a guess — measure
first, then allow roughly an order of magnitude of headroom. A relay measured at
≈0.7 ephemeral events/sec:

```sh
RL_EPHEMERAL_RATE_PER_SEC=5 RL_EPHEMERAL_BURST=30
```

Disabled by default (`0`), so existing deployments are unaffected.

## Config file & hot-reload

Set `RL_CONFIG_FILE=/path/to/strfry-ratelimit.conf` to load settings from a file instead of
environment variables. The file is `key = value` (`#` starts a comment); keys are the env names
**without** the `RL_` prefix, lowercased — e.g. `window_seconds`, `max_events`, `block_kinds`,
`ban_list_file`. See [`examples/strfry-ratelimit.conf`](examples/strfry-ratelimit.conf).

The plugin **re-reads the config file and the banlist when they change (by mtime)**, so you can
adjust `block_kinds`, rate limits, exemptions, and bans/unbans **without restarting strfry**.
In-memory rate-limit state is preserved across reloads. (A change is detected within a few dozen
processed events — effectively immediate on a busy relay.)

If `RL_CONFIG_FILE` is unset, configuration comes from environment variables exactly as before
(no hot-reload).

## Notes

- strfry calls the plugin synchronously (one event at a time), so per-event work must be cheap.
  This plugin does only a hashmap lookup + deque prune (microseconds), suitable for high-throughput
  relays.
- IP-based limiting is intentionally **not** enabled: the client IP is available in the request
  (`sourceInfo`), but banning IPs causes heavy collateral damage when legitimate aggregator relays
  or apps forward many users from one address. Pubkey-level limiting is the safer default.
- State is in memory; only bans persist (to `RL_BAN_LIST_FILE`).
- Parsing is dependency-free: the request line is byte-scanned for just `type`/`id`/`pubkey`/`kind`
  (a `"kind":` etc. inside a string value is escaped, so it never false-matches). No serde, no
  allocation per event.

## License

MIT
