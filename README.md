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
- **Per-pubkey sliding-window rate limit.** Up to `RL_MAX_EVENTS` distinct accepted event IDs per
  `RL_WINDOW_SECONDS` per pubkey. Re-delivery of an already accepted ID is not charged again, so
  direct and forwarded copies racing before strfry commits cannot inflate the count. A longer
  window separates one-time bursts from sustained spam.
- **Kind-class aware.** Only *accumulating* kinds are limited:
  - **Ephemeral** (20000–29999): never stored → exempt by default.
  - **Replaceable** (0, 3, 41, 10000–19999): only the latest per (pubkey,kind) is stored → exempt.
  - **Regular** + **Addressable** (30000–39999): can accumulate → limited.
  - Plus an explicit `RL_EXCLUDE_KINDS` list (default `7` = reactions).
- **Relay-wide ephemeral ceiling.** An optional global token-bucket cap on ephemeral events
  (`RL_EPHEMERAL_RATE_PER_SEC`), for *distributed* floods that spread across many pubkeys so no
  per-sender limit can see them. Kind-agnostic, so it survives an attacker switching kinds.
  Off by default — [see below](#relay-wide-ephemeral-ceiling-distributed-flood-defence).
- **Trusted-forwarder exemption.** Exact `sourceInfo` values in
  `RL_EXEMPT_RATE_LIMIT_SOURCES` skip only the per-pubkey window, preventing a known bridge's
  copies from being attributed to end users. Banlist checks and relay-wide ceilings still apply.
- **Optional auto-ban.** When `RL_BAN_ON_EXCEED=true`, a pubkey that exceeds the limit is banned
  (all its events rejected) and persisted to `RL_BAN_LIST_FILE`. Remove the line to unban.

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
| `RL_BLOCK_EPHEMERAL_SOURCES` | (none) | Exact comma-separated `sourceInfo` values whose ephemeral events (20000–29999) are blocked, e.g. client IPs or stream URLs |
| `RL_BLOCK_SOURCE_MODE` | `reject` | Verdict for source-specific blocking: `reject` (OK false with reason) or `shadow` (OK true, silently dropped) |
| `RL_EXEMPT_RATE_LIMIT_SOURCES` | (none) | Exact comma-separated trusted `sourceInfo` values excluded only from the per-pubkey window; global ceilings and existing bans still apply |
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
| `RL_TOTAL_RATE_PER_SEC` | `0` (off) | Relay-wide ceiling across **all** kinds, events/second — the backstop for a flood that moves outside the ephemeral range |
| `RL_TOTAL_BURST`       | auto    | Bucket depth for the all-kinds ceiling |
| `RL_CEILING_MODE`      | `reject`| How a ceiling answers a shed event: `reject` (OK false, `rate-limited:` reason — lets cooperative clients back off) or `shadow` (OK true, silently dropped) |

Example tuned for a busy relay (≈100 spam events/min must be caught, legit bursts ≈30 must pass):

```sh
RL_WINDOW_SECONDS=180 RL_MAX_EVENTS=100 RL_BAN_ON_EXCEED=true \
RL_BAN_LIST_FILE=./strfry-db/banned-pubkeys.txt
```

### Source-specific ephemeral blocking

`RL_BLOCK_EPHEMERAL_SOURCES` blocks ephemeral events only when the writePolicy
`sourceInfo` exactly matches a configured value. For direct relay connections,
`sourceInfo` is the client IP (or the address restored by strfry's
`realIpHeader`); for stream/sync inputs it is the upstream URL. This is useful
when one known forwarding relay contributes unwanted ephemeral traffic but
other clients must retain full ephemeral support:

```sh
RL_BLOCK_EPHEMERAL_SOURCES=149.28.29.200,2001:db8::10
RL_BLOCK_SOURCE_MODE=shadow
```

Non-ephemeral events from that source and all events from other sources remain
unaffected. Matching is exact and case-insensitive; keep configured addresses
updated if the upstream moves. Source-blocked events are rejected before shared
ceilings and therefore cannot drain their budgets. `shadow` avoids one strfry
INFO line per blocked event; use `reject` when the source can act on the reason.

### Duplicate delivery and trusted forwarders

strfry checks for an existing event before writePolicy, but copies arriving concurrently can both
pass that check before Writer commits either one. The plugin therefore remembers event IDs it
returns `accept` for during `RL_WINDOW_SECONDS`; another copy of the same ID still consumes the
relay-wide ceiling but is not charged to the pubkey again. Shed or per-pubkey-rejected IDs are not
cached, so retrying rejected traffic cannot bypass a limit.

A bridge can also race a writer outside the relay process, meaning writePolicy may see only the
bridge's already-stored copy. List trusted bridge IPs or stream URLs in
`RL_EXEMPT_RATE_LIMIT_SOURCES` to keep those copies out of end-user attribution:

```sh
RL_EXEMPT_RATE_LIMIT_SOURCES=149.28.29.200,2001:db8::10
```

This is deliberately narrower than a general allowlist. Existing bans are checked first, and every
attempt still consumes the relay-wide ceilings. Only the per-pubkey sliding window is skipped.
Use it only for sources you operate or intentionally trust.

### Relay-wide ephemeral ceiling (distributed-flood defence)

Per-pubkey limits cannot see a **distributed** flood: hundreds of pubkeys each
sending a modest rate sum to a firehose while every individual sender stays under
the limit. `RL_EPHEMERAL_RATE_PER_SEC` adds a single global token-bucket budget
for ephemeral kinds, which catches exactly that shape.

It is **kind-agnostic**, so unlike `RL_BLOCK_KINDS` it does not need to know
which kind is being abused and cannot be evaded by switching to another
ephemeral kind. (An attacker who leaves the ephemeral range entirely — e.g.
kind 1 — exits this ceiling and falls back on the per-pubkey limiter.)
Over-limit events are answered `["OK", id, false, "rate-limited: …"]` by
default. The `rate-limited:` prefix matters: it is the same one strfry's built-in
limiter uses, and cooperative clients key on it to back off (Trystero ≥ 0.25.4,
for example, widens its announce interval up to 15 minutes on seeing it). That
turns the ceiling from a wall into a signal, and a well-behaved source reduces
its own load. Set `RL_CEILING_MODE=shadow` to answer `shadowReject` instead
(sender sees OK, nothing is stored or broadcast) for a source you deliberately
don't want to tip off.

**Cost of `reject` you should know about:** strfry logs one INFO line per
rejected event (`write policy blocked event …: <reason>`) whenever the plugin
returns a non-empty reason, and nothing for `shadowReject`. Under a sustained
flood that is hundreds of log lines per second — measured ~0.9 GB/day on one
relay — and the logging itself cost ~10 percentage points of CPU. So choose
`reject` when the clients hitting you can actually act on the signal, and
`shadow` when they can't (e.g. the relay is no longer in any client's default
list, so only old clients reach it). Either way, rotate the relay log.

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

### All-kinds ceiling (`RL_TOTAL_RATE_PER_SEC`)

The ephemeral ceiling only covers 20000–29999. `RL_TOTAL_RATE_PER_SEC` is the
same mechanism applied to **every** kind, as a backstop for an attacker who
moves the same distributed flood to another range. An event that was already
shed by the ephemeral ceiling is not charged to this budget, so a flood cannot
consume it and starve normal traffic.

Set it well above your real peak, because it applies to legitimate traffic too —
including relay-to-relay sync bursts and backfills, which are far spikier than
client writes. Measure your **non-ephemeral peak**, then leave a large margin:
two relays measured here peaked at 4/s and 6/s non-ephemeral, so

```sh
RL_TOTAL_RATE_PER_SEC=50 RL_TOTAL_BURST=100
```

is ~8× the observed peak while still cutting a 4,000/s flood by 98%. This is a
last-resort cap on total load, not a spam filter — leave the per-pubkey limiter
to do the fine-grained work. Off by default.

## Config file & hot-reload

Set `RL_CONFIG_FILE=/path/to/strfry-ratelimit.conf` to load settings from a file instead of
environment variables. The file is `key = value` (`#` starts a comment); keys are the env names
**without** the `RL_` prefix, lowercased — e.g. `window_seconds`, `max_events`, `block_kinds`,
`block_ephemeral_sources`, `exempt_rate_limit_sources`, `ban_list_file`. See [`examples/strfry-ratelimit.conf`](examples/strfry-ratelimit.conf).

The plugin **re-reads the config file and the banlist when they change (by mtime)**, so you can
adjust blocked kinds/sources, rate limits, exemptions, and bans/unbans **without restarting strfry**.
In-memory rate-limit state is preserved across reloads. (A change is detected within a few dozen
processed events — effectively immediate on a busy relay.)

If `RL_CONFIG_FILE` is unset, configuration comes from environment variables exactly as before
(no hot-reload).

## Notes

- strfry calls the plugin synchronously (one event at a time), so per-event work must be cheap.
  This plugin does only bounded string/hash lookups + deque pruning (microseconds), suitable for
  high-throughput relays. Accepted-ID cache entries expire with the configured sliding window.
- IP-based limiting is intentionally **not** enabled: the client IP is available in the request
  (`sourceInfo`), but banning IPs causes heavy collateral damage when legitimate aggregator relays
  or apps forward many users from one address. Pubkey-level limiting is the safer default.
- State is in memory; only bans persist (to `RL_BAN_LIST_FILE`).
- Parsing is dependency-free: the request line is byte-scanned for just `type`/`id`/`pubkey`/`kind`/`sourceInfo`
  (a `"kind":` etc. inside a string value is escaped, so it never false-matches). No serde.

## License

MIT
