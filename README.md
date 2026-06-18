# strfry-ratelimit

A [strfry](https://github.com/hoytech/strfry) **writePolicy plugin** that rate-limits writes
per pubkey and (optionally) auto-bans abusers — without patching strfry itself. It runs as a
separate process that strfry talks to over stdin/stdout, so it works with stock/upstream strfry.

## What it does

- **Per-pubkey sliding-window rate limit.** Up to `RL_MAX_EVENTS` accepted per `RL_WINDOW_SECONDS`
  per pubkey. A longer window separates one-time bursts (fixed count) from sustained spam (which
  scales with the window), so a generous window tolerates legit bursts while still catching floods.
- **Kind-class aware.** Only *accumulating* kinds are limited:
  - **Ephemeral** (20000–29999): never stored → exempt by default.
  - **Replaceable** (0, 3, 41, 10000–19999): only the latest per (pubkey,kind) is stored → exempt.
  - **Regular** + **Addressable** (30000–39999): can accumulate → limited.
  - Plus an explicit `RL_EXCLUDE_KINDS` list (default `7` = reactions).
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
| `RL_WINDOW_SECONDS`    | `60`    | Sliding window length (seconds) |
| `RL_MAX_EVENTS`        | `10`    | Max accepted events per window per pubkey |
| `RL_MODE`              | `reject`| `reject` (OK false) or `shadow` (OK true but dropped) |
| `RL_BAN_ON_EXCEED`     | `false` | Permanently ban a pubkey that exceeds the limit |
| `RL_BAN_LIST_FILE`     | (none)  | Path to persist bans (64-char hex, one per line) |
| `RL_EXCLUDE_KINDS`     | `7`     | Comma-separated kinds to never limit |
| `RL_EXEMPT_EPHEMERAL`  | `true`  | Exempt ephemeral kinds (20000–29999) |
| `RL_EXEMPT_REPLACEABLE`| `true`  | Exempt replaceable kinds (0,3,41,10000–19999) |
| `RL_EXEMPT_ADDRESSABLE`| `false` | Exempt addressable kinds (30000–39999) |

Example tuned for a busy relay (≈100 spam events/min must be caught, legit bursts ≈30 must pass):

```sh
RL_WINDOW_SECONDS=180 RL_MAX_EVENTS=100 RL_BAN_ON_EXCEED=true \
RL_BAN_LIST_FILE=./strfry-db/banned-pubkeys.txt
```

## Notes

- strfry calls the plugin synchronously (one event at a time), so per-event work must be cheap.
  This plugin does only a hashmap lookup + deque prune (microseconds), suitable for high-throughput
  relays.
- IP-based limiting is intentionally **not** enabled: the client IP is available in the request
  (`sourceInfo`), but banning IPs causes heavy collateral damage when legitimate aggregator relays
  or apps forward many users from one address. Pubkey-level limiting is the safer default.
- State is in memory; only bans persist (to `RL_BAN_LIST_FILE`).

## License

MIT
