//! strfry writePolicy plugin: kind blocklist + per-pubkey rate limiting with optional auto-ban.
//!
//! strfry sends one JSON request per line on stdin and expects one JSON response per line on
//! stdout. See https://github.com/hoytech/strfry/blob/master/docs/plugins.md
//!
//! Parsing: instead of a full JSON parse we byte-scan the request line for only the fields we
//! need (type, id, pubkey, kind, sourceInfo). strfry's request is machine-generated, and any `"kind":` /
//! `"pubkey":` / `"id":` appearing inside a string *value* is escaped (`\"`), so these
//! key patterns never false-match content/tags. This drops the serde dependency and avoids a
//! full JSON parse and its allocations on every event. Whitespace after the colon is tolerated (compact or pretty JSON).
//!
//! Design:
//! - Kind blocklist (RL_BLOCK_KINDS) is checked first and drops matching kinds outright. Useful for
//!   ephemeral floods (e.g. relayed WebRTC signaling) that per-pubkey rate limiting cannot catch
//!   because each event uses a throwaway pubkey.
//! - Rate limiting applies only to "accumulating" kinds. Ephemeral (20000-29999) and replaceable
//!   (0/3/41/10000-19999) cannot be used for storage abuse and are exempt by default; addressable
//!   (30000-39999) is opt-in. A sliding window separates legit bursts from sustained spam. State is
//!   in-memory (single long-lived process); bans optionally persist to a file to survive restarts.
//! - Accepted event IDs are remembered for one sliding window so concurrent direct/forwarded
//!   copies cannot inflate a pubkey's count. Trusted forwarding sources can also be excluded from
//!   only the per-pubkey window while remaining subject to existing bans and global ceilings.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

struct Config {
    window_seconds: u64,
    max_events: u64,
    mode_shadow: bool,
    ban_on_exceed: bool,
    ban_list_file: Option<String>,
    exclude_kinds: HashSet<u64>,
    exempt_ephemeral: bool,
    exempt_replaceable: bool,
    exempt_addressable: bool,
    block_singles: Vec<u64>,
    block_ranges: Vec<(u64, u64)>,
    /// Exact writePolicy sourceInfo values whose ephemeral events are blocked. This allows a relay
    /// operator to suppress ephemeral forwarding from one upstream/source without disabling
    /// ephemeral events for direct clients or other relays.
    block_ephemeral_sources: HashSet<String>,
    /// `true` returns shadowReject for a blocked source; `false` returns an explicit rejection.
    block_source_shadow: bool,
    /// Exact writePolicy sourceInfo values excluded from the per-pubkey sliding window. These
    /// are trusted forwarders whose copies can race direct delivery of the same events. They
    /// still consume relay-wide ceilings, and the persistent banlist still applies.
    exempt_rate_limit_sources: HashSet<String>,
    /// Events whose `created_at` is older than this many seconds are not counted against the
    /// per-pubkey window (0 = off, every event counts). The window measures *arrival* time, so a
    /// relay/tool re-syncing an author's backlog (negentropy, outbox backfill, a reconnecting
    /// client flushing its queue) would otherwise ban the author for traffic they did not send.
    /// Old events still pass the banlist and relay-wide ceilings.
    count_max_age_seconds: u64,
    /// Directory for the per-event audit trail (`audit-YYYYMMDD.tsv`, UTC days). Unset = off.
    /// One line per decided event: arrival time, source, id, pubkey, kind, created_at, request
    /// bytes, action, reason. This is what the relay DB cannot answer later: who sent what from
    /// where, including rejected events that were never stored.
    audit_log_dir: Option<String>,
    /// What to do with chunked file uploads stored as app data (kind 30078 with a d tag of the
    /// form `file_<id>_<n>` and a large opaque payload): `off`, `ignore` (shadowReject: the
    /// sender sees OK, nothing is stored) or `ban` (reject and add the pubkey to the banlist).
    /// Seen 2026-09 as tens of MB of encrypted blobs split into 30 KiB chunks.
    file_chunk_action: FileChunkAction,
    /// Relay-wide ceiling on ephemeral events (kinds 20000-29999), in events per second.
    /// 0 disables it. Unlike the per-pubkey limit this is a single global budget, which is what
    /// catches a *distributed* flood: hundreds of pubkeys/IPs each sending a modest rate sum to a
    /// firehose that no per-sender limit can see. It is also kind-agnostic, so an attacker that
    /// switches to a different ephemeral kind is still capped.
    ephemeral_rate_per_sec: f64,
    /// Bucket depth for the above — how big an instantaneous burst is allowed through before the
    /// sustained rate applies (e.g. several clients starting a call at once).
    ephemeral_burst: f64,
    /// Relay-wide ceiling across ALL kinds, in events per second. 0 disables it. The ephemeral
    /// ceiling only covers 20000-29999; this is the backstop for an attacker who moves the same
    /// distributed flood to another kind range. Size it well above your real peak (including
    /// relay-to-relay sync bursts), since it applies to normal traffic too.
    total_rate_per_sec: f64,
    /// Bucket depth for the all-kinds ceiling.
    total_burst: f64,
    /// How a ceiling answers a shed event. `false` (default) = `reject` with a
    /// `rate-limited:` reason, which cooperative clients key on to back off (strfry's own
    /// limiter uses the same prefix; Trystero >= 0.25.4 honours it). `true` = `shadowReject`
    /// (sender sees OK, nothing stored) — useful against a source you don't want to tip off.
    ceiling_shadow: bool,
    /// Per-source sliding window (seconds), 0 = off. A source is the connecting address from
    /// `sourceInfo`: an IPv4 address, or the /64 of an IPv6 address. Non-IP sources (stream/sync
    /// upstream URLs) and `exempt_rate_limit_sources` are never counted. It counts the same events as
    /// the per-pubkey window, summed over every pubkey from that source. This catches a sender that
    /// rotates throwaway keys to stay under the per-pubkey limit.
    source_window_seconds: u64,
    /// Events allowed per source within `source_window_seconds`.
    source_max_events: u64,
    /// `true`: a source that exceeds the limit is banned. All of its events, every kind and every
    /// pubkey, are rejected until the line is removed from `source_ban_list_file`. `false`: excess
    /// events are rejected with `rate-limited:` and the source is not banned.
    source_ban_on_exceed: bool,
    /// Persisted source bans (one IPv4 or IPv6 address/prefix per line; IPv6 is stored and
    /// matched as /64). Hot-reloaded on mtime change, so deleting a line unbans.
    source_ban_list_file: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum FileChunkAction {
    Off,
    Ignore,
    Ban,
}

/// Payload size at or above which a `file_<id>_<n>` kind-30078 event is treated as a file chunk.
const FILE_CHUNK_MIN_CONTENT: usize = 8192;

/// `file_` + one or more [A-Za-z0-9] + `_` + one or more digits, nothing else.
fn is_file_chunk_dtag(d: &[u8]) -> bool {
    let Some(rest) = d.strip_prefix(b"file_") else {
        return false;
    };
    let Some(us) = rest.iter().rposition(|&b| b == b'_') else {
        return false;
    };
    let (name, num) = (&rest[..us], &rest[us + 1..]);
    !name.is_empty()
        && name.iter().all(|b| b.is_ascii_alphanumeric())
        && !num.is_empty()
        && num.iter().all(|b| b.is_ascii_digit())
}

/// First `["d","..."]` tag value in the raw request, if any.
fn scan_dtag(buf: &[u8]) -> &[u8] {
    let Some(t) = find(buf, b"\"tags\":") else {
        return b"";
    };
    let tail = &buf[t..];
    let Some(p) = find(tail, b"[\"d\",\"") else {
        return b"";
    };
    let start = p + 6;
    let end = tail[start..].iter().position(|&b| b == b'"').map(|e| start + e).unwrap_or(start);
    &tail[start..end]
}

/// Reason attached to a ceiling `reject`. The `rate-limited:` prefix is load-bearing: it is
/// what well-behaved clients match on to slow down, so keep it even if the wording changes.
const CEILING_REJECT_MSG: &str = "rate-limited: relay ceiling exceeded, slow down";

/// Verdict for an event a ceiling decided to shed.
fn shed_verdict(cfg: &Config) -> (&'static str, &'static str) {
    if cfg.ceiling_shadow {
        ("shadowReject", "")
    } else {
        ("reject", CEILING_REJECT_MSG)
    }
}

/// Token bucket for the relay-wide ephemeral ceiling. Refills at `rate` tokens/sec up to
/// `burst`; each ephemeral event costs one token. Empty bucket => shed the event.
struct TokenBucket {
    tokens: f64,
    /// Monotonic, so an NTP step or suspend/resume can neither freeze the bucket nor grant a
    /// free refill (which a wall clock would).
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(burst: f64) -> Self {
        TokenBucket {
            tokens: burst,
            last: std::time::Instant::now(),
        }
    }
    /// Try to spend one token, refilling first. Returns false when the budget is exhausted.
    fn allow(&mut self, rate: f64, burst: f64) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shed accounting for one ceiling: counts events dropped and logs at most once per 10s, so a
/// sustained flood cannot spam the log while a later, separate episode is still reported (a
/// count-based throttle would silently skip it).
#[derive(Default)]
struct ShedMeter {
    total: u64,
    logged: u64,
    last: Option<std::time::Instant>,
}

impl ShedMeter {
    fn record(&mut self, kind: u64, label: &str, rate: f64, burst: f64) {
        self.total = self.total.wrapping_add(1);
        let now = std::time::Instant::now();
        let since = self.last.map(|t| now.duration_since(t).as_secs_f64());
        // clippy suggests `is_none_or`, which needs Rust 1.82 — kept as `map_or` so the plugin
        // still builds on the rustc shipped by Ubuntu 24.04 / Debian bookworm.
        #[allow(clippy::unnecessary_map_or)]
        if since.map_or(true, |s| s >= 10.0) {
            match since {
                None => eprintln!(
                    "strfry-ratelimit: {label} ({rate}/s burst {burst}) engaged, shedding events (latest kind {kind})"
                ),
                Some(s) => eprintln!(
                    "strfry-ratelimit: {label} ({rate}/s burst {burst}) shed {} events in the last {s:.0}s (total {}, latest kind {kind})",
                    self.total.wrapping_sub(self.logged), self.total
                ),
            }
            self.last = Some(now);
            self.logged = self.total;
        }
    }

    fn record_source_block(&mut self, kind: u64, source: &str) {
        self.total = self.total.wrapping_add(1);
        let now = std::time::Instant::now();
        let since = self.last.map(|t| now.duration_since(t).as_secs_f64());
        #[allow(clippy::unnecessary_map_or)]
        if since.map_or(true, |s| s >= 10.0) {
            match since {
                None => eprintln!(
                    "strfry-ratelimit: blocked ephemeral source {source} engaged (latest kind {kind})"
                ),
                Some(s) => eprintln!(
                    "strfry-ratelimit: blocked ephemeral source {source} dropped {} events in the last {s:.0}s (total {}, latest kind {kind})",
                    self.total.wrapping_sub(self.logged), self.total
                ),
            }
            self.last = Some(now);
            self.logged = self.total;
        }
    }
}

/// File modification time, or None if the path is unset/unreadable. Used to detect edits to the
/// config file and banlist file so they can be reloaded without restarting.
fn mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}
/// Strip a trailing `# comment`. `#` only starts a comment at line start or after whitespace, so a
/// `#` inside a value (e.g. a file path) is preserved.
fn strip_comment(line: &str) -> &str {
    let mut prev_ws = true; // start of line counts as "preceded by whitespace"
    for (i, b) in line.bytes().enumerate() {
        if b == b'#' && prev_ws {
            return &line[..i];
        }
        prev_ws = b == b' ' || b == b'\t';
    }
    line
}
/// Parse a kind spec like "20001, 22000-22999" into (single kinds, inclusive ranges).
fn parse_kind_list(spec: &str) -> (Vec<u64>, Vec<(u64, u64)>) {
    let (mut singles, mut ranges) = (Vec::new(), Vec::new());
    for part in spec.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((a, b)) = p.split_once('-') {
            match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                (Ok(a), Ok(b)) => ranges.push((a.min(b), a.max(b))),
                _ => eprintln!("strfry-ratelimit: ignoring unparseable RL_BLOCK_KINDS range {p:?}"),
            }
        } else if let Ok(k) = p.parse::<u64>() {
            singles.push(k);
        } else {
            eprintln!("strfry-ratelimit: ignoring unparseable RL_BLOCK_KINDS token {p:?}");
        }
    }
    (singles, ranges)
}

impl Config {
    /// Build from a key lookup. `get("window_seconds")` returns the raw value if set. This backs
    /// both env vars and the optional config file, so both share one set of parsing and defaults.
    fn from_lookup<F: Fn(&str) -> Option<String>>(get: F) -> Self {
        let u64_of = |k: &str, d: u64| get(k).and_then(|v| v.trim().parse().ok()).unwrap_or(d);
        let bool_of = |k: &str, d: bool| {
            get(k)
                .map(|v| {
                    matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(d)
        };
        let kinds_of = |k: &str, d: &[u64]| -> HashSet<u64> {
            get(k)
                .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
                .unwrap_or_else(|| d.iter().copied().collect())
        };
        // Non-negative finite float. An unusable value (e.g. a typo like `5/s`) is warned about
        // loudly and then treated as 0/absent — so check the log after editing: a bad
        // `ephemeral_rate_per_sec` leaves the ceiling OFF, it does not fail closed.
        let f64_of = |k: &str| -> f64 {
            match get(k) {
                None => 0.0,
                Some(v) => match v.trim().parse::<f64>() {
                    Ok(f) if f.is_finite() && f >= 0.0 => f,
                    _ => {
                        eprintln!("strfry-ratelimit: ignoring invalid {k} value {:?} (want a non-negative number)", v.trim());
                        0.0
                    }
                },
            }
        };
        let rate = f64_of("ephemeral_rate_per_sec");
        // A ceiling with burst < 1 can never issue a token, which would silently shed 100% of
        // ephemeral traffic. Raise it to a usable depth rather than blackholing the relay.
        let mut burst = f64_of("ephemeral_burst");
        if rate > 0.0 && burst < 1.0 {
            let fixed = rate.max(1.0);
            eprintln!(
                "strfry-ratelimit: ephemeral_burst {burst} is too small to ever allow an event; using {fixed}. Set ephemeral_burst explicitly (>= 1)."
            );
            burst = fixed;
        }
        let total_rate = f64_of("total_rate_per_sec");
        let mut total_burst = f64_of("total_burst");
        if total_rate > 0.0 && total_burst < 1.0 {
            let fixed = total_rate.max(1.0);
            eprintln!(
                "strfry-ratelimit: total_burst {total_burst} is too small to ever allow an event; using {fixed}. Set total_burst explicitly (>= 1)."
            );
            total_burst = fixed;
        }
        // reject is the fail-safe: the event is still not stored, and the client still gets the
        // back-off signal. Warn on a typo so an operator who meant `shadow` finds out.
        let ceiling_shadow = match get("ceiling_mode").map(|m| m.trim().to_ascii_lowercase()) {
            None => false,
            Some(m) if m.is_empty() || m == "reject" => false,
            Some(m) if m == "shadow" => true,
            Some(m) => {
                eprintln!("strfry-ratelimit: ignoring invalid ceiling_mode value {m:?} (want reject or shadow); using reject");
                false
            }
        };
        let (block_singles, block_ranges) =
            parse_kind_list(&get("block_kinds").unwrap_or_default());
        let block_ephemeral_sources = get("block_ephemeral_sources")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let block_source_shadow = match get("block_source_mode")
            .map(|m| m.trim().to_ascii_lowercase())
        {
            None => false,
            Some(m) if m.is_empty() || m == "reject" => false,
            Some(m) if m == "shadow" => true,
            Some(m) => {
                eprintln!("strfry-ratelimit: ignoring invalid block_source_mode value {m:?} (want reject or shadow); using reject");
                false
            }
        };
        let exempt_rate_limit_sources = get("exempt_rate_limit_sources")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Config {
            window_seconds: u64_of("window_seconds", 60),
            max_events: u64_of("max_events", 10),
            mode_shadow: get("mode").map(|m| m.trim() == "shadow").unwrap_or(false),
            ban_on_exceed: bool_of("ban_on_exceed", false),
            ban_list_file: get("ban_list_file").filter(|s| !s.is_empty()),
            exclude_kinds: kinds_of("exclude_kinds", &[7]),
            exempt_ephemeral: bool_of("exempt_ephemeral", true),
            exempt_replaceable: bool_of("exempt_replaceable", true),
            exempt_addressable: bool_of("exempt_addressable", false),
            block_singles,
            block_ranges,
            block_ephemeral_sources,
            block_source_shadow,
            exempt_rate_limit_sources,
            count_max_age_seconds: u64_of("count_max_age_seconds", 0),
            file_chunk_action: match get("file_chunk_action").map(|v| v.trim().to_ascii_lowercase()) {
                None => FileChunkAction::Off,
                Some(v) if v.is_empty() || v == "off" => FileChunkAction::Off,
                Some(v) if v == "ignore" || v == "shadow" => FileChunkAction::Ignore,
                Some(v) if v == "ban" => FileChunkAction::Ban,
                Some(v) => {
                    eprintln!("strfry-ratelimit: ignoring invalid file_chunk_action value {v:?} (want off, ignore or ban)");
                    FileChunkAction::Off
                }
            },
            audit_log_dir: get("audit_log_dir").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            ephemeral_rate_per_sec: rate,
            ephemeral_burst: burst,
            total_rate_per_sec: total_rate,
            total_burst,
            ceiling_shadow,
            source_window_seconds: u64_of("source_window_seconds", 0),
            source_max_events: u64_of("source_max_events", 0),
            source_ban_on_exceed: bool_of("source_ban_on_exceed", false),
            source_ban_list_file: get("source_ban_list_file")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }
    /// Config from environment variables: generic key `foo_bar` reads env `RL_FOO_BAR`.
    fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(format!("RL_{}", k.to_ascii_uppercase())).ok())
    }
    /// Config from a `key = value` file, or `None` if the file can't be read or is empty/whitespace
    /// (e.g. a transient truncation while an editor rewrites it) — the caller then keeps its
    /// last-good config instead of reverting to defaults. `#` starts a comment; blank lines and
    /// unknown keys are ignored. Keys are the generic names (e.g. `window_seconds`, `block_kinds`).
    fn from_file(path: &str) -> Option<Config> {
        let txt = std::fs::read_to_string(path).ok()?;
        if txt.trim().is_empty() {
            return None;
        }
        let mut map: HashMap<String, String> = HashMap::new();
        for line in txt.lines() {
            let line = strip_comment(line).trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        Some(Self::from_lookup(|k| map.get(k).cloned()))
    }
    fn is_blocked(&self, kind: u64) -> bool {
        self.block_singles.contains(&kind)
            || self
                .block_ranges
                .iter()
                .any(|&(lo, hi)| lo <= kind && kind <= hi)
    }
    fn blocks_ephemeral_source(&self, kind: u64, source: &str) -> bool {
        is_ephemeral(kind)
            && !source.is_empty()
            && self
                .block_ephemeral_sources
                .contains(&source.to_ascii_lowercase())
    }
    fn exempts_rate_limit_source(&self, source: &str) -> bool {
        !source.is_empty()
            && self
                .exempt_rate_limit_sources
                .contains(&source.to_ascii_lowercase())
    }
}

fn is_replaceable(kind: u64) -> bool {
    kind == 0 || kind == 3 || kind == 41 || (10_000..20_000).contains(&kind)
}
fn is_ephemeral(kind: u64) -> bool {
    (20_000..30_000).contains(&kind)
}
fn is_addressable(kind: u64) -> bool {
    (30_000..40_000).contains(&kind)
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// First index of `needle` in `hay`, or None.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
fn skip_ws(buf: &[u8], mut i: usize) -> usize {
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t') {
        i += 1;
    }
    i
}
/// The string value for a colon-terminated key, e.g. `key = b"\"pubkey\":"`. Empty if not found.
fn scan_str<'a>(buf: &'a [u8], key: &[u8]) -> &'a [u8] {
    if let Some(p) = find(buf, key) {
        let i = skip_ws(buf, p + key.len());
        if i < buf.len() && buf[i] == b'"' {
            let start = i + 1;
            let mut end = start;
            while end < buf.len() && buf[end] != b'"' {
                end += 1;
            }
            return &buf[start..end];
        }
    }
    b""
}
/// The unsigned-integer value for a colon-terminated key, e.g. `key = b"\"kind\":"`.
fn scan_u64(buf: &[u8], key: &[u8]) -> Option<u64> {
    let p = find(buf, key)?;
    let mut i = skip_ws(buf, p + key.len());
    let (mut n, mut any) = (0u64, false);
    while i < buf.len() && buf[i].is_ascii_digit() {
        n = n.wrapping_mul(10).wrapping_add((buf[i] - b'0') as u64);
        i += 1;
        any = true;
    }
    if any {
        Some(n)
    } else {
        None
    }
}

fn load_banlist(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue; // comments / blank lines
            }
            if line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()) {
                set.insert(line.to_ascii_lowercase());
            }
        }
    }
    set
}
/// Rate-limit/ban key for a `sourceInfo` value: the IPv4 address itself, or `a:b:c:d::/64` for
/// IPv6 (one subscriber line usually owns a whole /64 and can rotate within it). A trailing
/// `/len` is ignored, so a banlist line may be written as an address or as a prefix. `None` for
/// anything that is not an IP (e.g. an upstream relay URL from stream/sync).
fn source_key(source: &str) -> Option<String> {
    let addr = source.trim().split('/').next().unwrap_or("");
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    match addr.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return Some(v4.to_string());
            }
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
        }
    }
}
fn load_source_banlist(path: &str) -> HashSet<String> {
    std::fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .map(|l| strip_comment(l).trim())
                .filter(|l| !l.is_empty())
                .filter_map(source_key)
                .collect()
        })
        .unwrap_or_default()
}
fn append_ban(path: &str, pubkey: &str) {
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{pubkey}");
        }
        Err(e) => eprintln!("strfry-ratelimit: failed to persist ban for {pubkey} to {path}: {e}"),
    }
}

/// Per-event facts for the audit trail, filled in as the request is parsed.
#[derive(Default)]
struct Ctx {
    source: String,
    pubkey: String,
    kind: String,
    created_at: String,
    bytes: usize,
}

/// Civil date (UTC) for a unix day number. Howard Hinnant's days_from_civil inverse.
fn ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Append-only daily audit file. Failures are reported once per day and never affect verdicts.
#[derive(Default)]
struct Audit {
    dir: Option<String>,
    day: i64,
    file: Option<std::fs::File>,
    warned_day: i64,
}

impl Audit {
    fn write(&mut self, dir: &Option<String>, id: &[u8], action: &str, msg: &str, c: &Ctx) {
        let Some(d) = dir else {
            self.file = None;
            self.dir = None;
            return;
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let day = (now.as_secs() / 86400) as i64;
        if self.file.is_none() || self.day != day || self.dir.as_deref() != Some(d.as_str()) {
            let (y, m, dd) = ymd(day);
            let path = format!("{d}/audit-{y:04}{m:02}{dd:02}.tsv");
            self.file = OpenOptions::new().create(true).append(true).open(&path).ok();
            self.day = day;
            self.dir = Some(d.clone());
            if self.file.is_none() && self.warned_day != day {
                self.warned_day = day;
                eprintln!("strfry-ratelimit: audit log {path} not writable");
            }
        }
        if let Some(f) = &mut self.file {
            let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
            let line = format!(
                "{}.{:03}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                now.as_secs(),
                now.subsec_millis(),
                clean(&c.source),
                clean(std::str::from_utf8(id).unwrap_or("")),
                clean(&c.pubkey),
                c.kind,
                c.created_at,
                c.bytes,
                action,
                msg
            );
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Write one response line (and its audit record). `id` is 64-char hex and `action`/`msg` are
/// fixed ASCII literals, so no JSON string escaping is needed.
#[allow(clippy::too_many_arguments)]
fn respond(
    out: &mut impl Write,
    audit: &mut Audit,
    dir: &Option<String>,
    ctx: &Ctx,
    id: &[u8],
    action: &str,
    msg: &str,
) {
    let _ = out.write_all(b"{\"id\":\"");
    let _ = out.write_all(id);
    let _ = out.write_all(b"\",\"action\":\"");
    let _ = out.write_all(action.as_bytes());
    let _ = out.write_all(b"\",\"msg\":\"");
    let _ = out.write_all(msg.as_bytes());
    let _ = out.write_all(b"\"}\n");
    let _ = out.flush();
    audit.write(dir, id, action, msg, ctx);
}

fn main() {
    // Config from a file if RL_CONFIG_FILE is set (hot-reloaded on mtime change), else from
    // environment variables (read once at startup — fully backward compatible).
    let cfg_path = std::env::var("RL_CONFIG_FILE")
        .ok()
        .filter(|s| !s.is_empty());
    let mut cfg = match &cfg_path {
        Some(p) => Config::from_file(p).unwrap_or_else(|| {
            eprintln!(
                "strfry-ratelimit: config file {p} unreadable/empty at startup; using defaults"
            );
            Config::from_lookup(|_| None)
        }),
        None => Config::from_env(),
    };
    let mut cfg_mtime = cfg_path.as_deref().and_then(mtime);

    // Banlist is loaded from cfg.ban_list_file and also hot-reloaded on its own mtime change, so
    // manual edits (unbans/bans) take effect without a restart.
    let mut ban_path = cfg.ban_list_file.clone();
    let mut banned: HashSet<String> = ban_path.as_deref().map(load_banlist).unwrap_or_default();
    let mut ban_mtime = ban_path.as_deref().and_then(mtime);

    let mut buckets: HashMap<String, VecDeque<u64>> = HashMap::new();
    let mut source_buckets: HashMap<String, VecDeque<u64>> = HashMap::new();
    let mut source_ban_path = cfg.source_ban_list_file.clone();
    let mut banned_sources: HashSet<String> = source_ban_path
        .as_deref()
        .map(load_source_banlist)
        .unwrap_or_default();
    let mut source_ban_mtime = source_ban_path.as_deref().and_then(mtime);
    // Event IDs that this plugin accepted recently. strfry's Ingester checks the DB before
    // writePolicy, but two sources can both pass that check before Writer commits either copy.
    // Remembering accepted IDs prevents that race from charging one logical event twice.
    let mut accepted_ids: HashSet<String> = HashSet::new();
    let mut accepted_id_order: VecDeque<(u64, String)> = VecDeque::new();
    // Relay-wide ephemeral budget. Sized from the current config; a hot-reload that raises the
    // burst is picked up by allow()'s clamp on the next event.
    let mut eph_bucket = TokenBucket::new(cfg.ephemeral_burst);
    let mut total_bucket = TokenBucket::new(cfg.total_burst);
    let mut eph_meter = ShedMeter::default();
    let mut total_meter = ShedMeter::default();
    let mut source_block_meter = ShedMeter::default();

    eprintln!(
        "strfry-ratelimit: sourceLimit={} sourceBanOnExceed={} sourceBanList={:?} banned_sources_loaded={}",
        if cfg.source_window_seconds > 0 && cfg.source_max_events > 0 {
            format!("{}/{}s", cfg.source_max_events, cfg.source_window_seconds)
        } else {
            "off".to_string()
        },
        cfg.source_ban_on_exceed,
        cfg.source_ban_list_file,
        banned_sources.len()
    );
    eprintln!(
        "strfry-ratelimit: source={} window={}s max={} banOnExceed={} blockSingles={:?} blockRanges={:?} blockEphemeralSources={:?} blockSourceMode={} exemptRateLimitSources={:?} countMaxAge={}s fileChunk={:?} excludeKinds={:?} exempt(eph={},repl={},addr={}) ephemeralCeiling={} totalCeiling={} ceilingMode={} banned_loaded={}",
        cfg_path.as_deref().unwrap_or("env"), cfg.window_seconds, cfg.max_events, cfg.ban_on_exceed,
        cfg.block_singles, cfg.block_ranges, cfg.block_ephemeral_sources,
        if cfg.block_source_shadow { "shadow" } else { "reject" }, cfg.exempt_rate_limit_sources, cfg.count_max_age_seconds, cfg.file_chunk_action, cfg.exclude_kinds,
        cfg.exempt_ephemeral, cfg.exempt_replaceable, cfg.exempt_addressable,
        if cfg.ephemeral_rate_per_sec > 0.0 {
            format!("{}/s burst {}", cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst)
        } else {
            "off".to_string()
        },
        if cfg.total_rate_per_sec > 0.0 {
            format!("{}/s burst {}", cfg.total_rate_per_sec, cfg.total_burst)
        } else {
            "off".to_string()
        },
        if cfg.ceiling_shadow { "shadow" } else { "reject" },
        banned.len()
    );

    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut line: Vec<u8> = Vec::with_capacity(8192);
    let mut processed: u64 = 0;
    let mut audit = Audit::default();
    let mut tick: u64 = 0;

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        // Hot-reload config + banlist periodically (throttled; a cheap mtime stat, no re-read
        // unless the file actually changed). In-memory rate-limit state is preserved across reloads.
        tick = tick.wrapping_add(1);
        // Keep modulo syntax compatible with the Rust 1.81 toolchain on Ubuntu 24.04.
        #[allow(clippy::manual_is_multiple_of)]
        if tick % 64 == 0 {
            if let Some(p) = &cfg_path {
                let m = mtime(p);
                // Only reload when the file still exists and actually changed. If it briefly
                // vanishes (mtime None, e.g. a delete-then-write editor), keep the last good
                // config instead of silently reverting every setting to its default.
                if m.is_some() && m != cfg_mtime {
                    if let Some(new_cfg) = Config::from_file(p) {
                        cfg = new_cfg;
                        cfg_mtime = m; // commit only on a successful (non-empty) read
                        if cfg.ban_list_file != ban_path {
                            ban_path = cfg.ban_list_file.clone();
                            banned = ban_path.as_deref().map(load_banlist).unwrap_or_default();
                            ban_mtime = ban_path.as_deref().and_then(mtime);
                        }
                        if cfg.source_ban_list_file != source_ban_path {
                            source_ban_path = cfg.source_ban_list_file.clone();
                            banned_sources = source_ban_path
                                .as_deref()
                                .map(load_source_banlist)
                                .unwrap_or_default();
                            source_ban_mtime = source_ban_path.as_deref().and_then(mtime);
                        }
                        eprintln!(
                            "strfry-ratelimit: reloaded config from {p} (blockEphemeralSources={:?} blockSourceMode={} exemptRateLimitSources={:?} ephemeralCeiling={} totalCeiling={} ceilingMode={})",
                            cfg.block_ephemeral_sources,
                            if cfg.block_source_shadow { "shadow" } else { "reject" },
                            cfg.exempt_rate_limit_sources,
                            if cfg.ephemeral_rate_per_sec > 0.0 {
                                format!("{}/s burst {}", cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst)
                            } else {
                                "off".to_string()
                            },
                            if cfg.total_rate_per_sec > 0.0 {
                                format!("{}/s burst {}", cfg.total_rate_per_sec, cfg.total_burst)
                            } else {
                                "off".to_string()
                            },
                            if cfg.ceiling_shadow { "shadow" } else { "reject" }
                        );
                    }
                    // read failed / empty (e.g. mid-write): keep last-good config and retry later.
                }
            }
            if let Some(p) = &ban_path {
                let m = mtime(p);
                if m.is_some() && m != ban_mtime {
                    banned = load_banlist(p);
                    ban_mtime = m;
                }
            }
            if let Some(p) = &source_ban_path {
                let m = mtime(p);
                if m.is_some() && m != source_ban_mtime {
                    banned_sources = load_source_banlist(p);
                    source_ban_mtime = m;
                }
            }
        }

        let buf = &line[..];
        if buf.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }

        let id = scan_str(buf, b"\"id\":");

        // strfry currently only sends type "new"; accept anything else untouched.
        if let Some(p) = find(buf, b"\"type\":") {
            let i = skip_ws(buf, p + 7);
            if buf.get(i..i + 5) != Some(b"\"new\"") {
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &Ctx::default(), id, "accept", "");
                continue;
            }
        }

        let kind = scan_u64(buf, b"\"kind\":");
        let source = std::str::from_utf8(scan_str(buf, b"\"sourceInfo\":")).unwrap_or("");
        let ctx = if cfg.audit_log_dir.is_some() {
            Ctx {
                source: source.to_string(),
                pubkey: String::from_utf8_lossy(scan_str(buf, b"\"pubkey\":")).into_owned(),
                kind: kind.map(|k| k.to_string()).unwrap_or_default(),
                created_at: scan_u64(buf, b"\"created_at\":")
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                bytes: buf.len(),
            }
        } else {
            Ctx::default()
        };

        // 1) Kind blocklist — cheap, drops floods outright before we extract pubkey or touch state.
        if let Some(k) = kind {
            if cfg.is_blocked(k) {
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "blocked: kind not accepted here");
                continue;
            }
        }

        // 1a) Banned source (connecting address): every kind, every pubkey. Checked before the
        //     ceilings so a banned sender cannot drain the shared budget.
        let src_key = if cfg.exempts_rate_limit_source(source) {
            None
        } else {
            source_key(source)
        };
        if let Some(sk) = &src_key {
            if !banned_sources.is_empty() && banned_sources.contains(sk) {
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "blocked: source is banned");
                continue;
            }
        }

        // 1b) Source-specific ephemeral block. `sourceInfo` is the original client IP for relay
        // connections (including Cloudflare realIpHeader) and the upstream URL for stream/sync.
        // Check this before shared ceilings so blocked upstream traffic cannot drain their budget.
        if let Some(k) = kind {
            if cfg.blocks_ephemeral_source(k, source) {
                source_block_meter.record_source_block(k, source);
                let (action, msg) = if cfg.block_source_shadow {
                    ("shadowReject", "")
                } else {
                    (
                        "reject",
                        "blocked: ephemeral events from this source are not accepted",
                    )
                };
                // Not audited: a configured upstream's ephemeral firehose is high-volume, already
                // summarized by source_block_meter, and attributes nothing to an end user.
                respond(&mut out, &mut audit, &None, &ctx, id, action, msg);
                continue;
            }
        }

        // pubkey should be 64 hex; None if unreadable (then it can't be banned or rate-limited).
        let pubkey = match std::str::from_utf8(scan_str(buf, b"\"pubkey\":")) {
            Ok(s) if !s.is_empty() => Some(s.to_ascii_lowercase()),
            _ => None,
        };

        // 2) Banlist — checked before any fail-open accept, so a ban can't be bypassed by a
        //    malformed kind/pubkey field.
        if let Some(pk) = &pubkey {
            if !banned.is_empty() && banned.contains(pk) {
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "blocked: pubkey is banned");
                continue;
            }
        }

        // 2a) Chunked file uploads disguised as app data. Checked after the banlist (a banned
        //     uploader is already rejected) and before the ceilings, so it costs no budget.
        if cfg.file_chunk_action != FileChunkAction::Off
            && kind == Some(30078)
            && is_file_chunk_dtag(scan_dtag(buf))
            && scan_str(buf, b"\"content\":").len() >= FILE_CHUNK_MIN_CONTENT
        {
            match (cfg.file_chunk_action, &pubkey) {
                (FileChunkAction::Ban, Some(pk)) => {
                    banned.insert(pk.clone());
                    buckets.remove(pk);
                    if let Some(path) = &cfg.ban_list_file {
                        append_ban(path, pk);
                    }
                    eprintln!("strfry-ratelimit: BANNED {pk} (file chunk upload)");
                    respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "blocked: pubkey is banned (file upload not accepted)");
                }
                _ => {
                    respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "shadowReject", "file chunk ignored");
                }
            }
            continue;
        }

        // 2b) Relay-wide ceilings. Run AFTER the banlist so an already-banned pubkey cannot
        //     drain a shared budget, but BEFORE the per-pubkey limit, because a distributed flood
        //     spreads itself thin across many pubkeys and only a global budget can see it.
        //     Kind-agnostic, so switching kinds does not evade them.
        //     A shed event falls through to the per-pubkey window below rather than returning
        //     here, so with `exempt_ephemeral = false` a single-source flood still trips
        //     `ban_on_exceed`. Under the default `exempt_ephemeral = true` ephemeral kinds never
        //     reach that window, so the ceiling caps the flood but nothing is banned for it.
        let mut shed = false;
        if let Some(k) = kind {
            // Ephemeral ceiling: the tight budget for the range floods actually use.
            if cfg.ephemeral_rate_per_sec > 0.0
                && is_ephemeral(k)
                && !eph_bucket.allow(cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst)
            {
                shed = true;
                eph_meter.record(
                    k,
                    "ephemeral ceiling",
                    cfg.ephemeral_rate_per_sec,
                    cfg.ephemeral_burst,
                );
            }
            // All-kinds ceiling: the backstop for a flood that moves outside 20000-29999.
            // Charged only if the event survived above, so one event never costs two budgets.
            if !shed
                && cfg.total_rate_per_sec > 0.0
                && !total_bucket.allow(cfg.total_rate_per_sec, cfg.total_burst)
            {
                shed = true;
                total_meter.record(
                    k,
                    "all-kinds ceiling",
                    cfg.total_rate_per_sec,
                    cfg.total_burst,
                );
            }
        }

        // Rate limiting needs a readable kind and pubkey; otherwise accept (fail open).
        let (kind, pubkey) = match (kind, pubkey) {
            (Some(k), Some(pk)) => (k, pk),
            _ => {
                // Nothing to rate-limit against, but a shed event must still not be stored.
                {
                    let (action, msg) = if shed {
                        shed_verdict(&cfg)
                    } else {
                        ("accept", "")
                    };
                    respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, action, msg);
                }
                continue;
            }
        };

        // 3) Is this kind subject to rate limiting?
        let subject = !(cfg.exclude_kinds.contains(&kind)
            || (cfg.exempt_ephemeral && is_ephemeral(kind))
            || (cfg.exempt_replaceable && is_replaceable(kind))
            || (cfg.exempt_addressable && is_addressable(kind)));
        // Backlog/sync traffic: an event authored long before it arrived says nothing about how
        // fast its author is posting now. Future-dated events are still counted.
        let stale = cfg.count_max_age_seconds > 0
            && scan_u64(buf, b"\"created_at\":")
                .map(|t| t.saturating_add(cfg.count_max_age_seconds) < now_secs())
                .unwrap_or(false);
        if !subject || stale || cfg.exempts_rate_limit_source(source) {
            // Exempt from the per-pubkey limiter, but the ceiling still applies. Trusted
            // forwarders are exempted only from attribution/BAN because their copies can race
            // direct delivery; their traffic still consumes the relay's global budget.
            {
                let (action, msg) = if shed {
                    shed_verdict(&cfg)
                } else {
                    ("accept", "")
                };
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, action, msg);
            }
            continue;
        }

        // 4) Count each accepted logical event ID at most once per sliding window. This cache is
        // deliberately checked after the global ceiling (all network attempts still cost relay
        // capacity) and stores only events we return `accept` for below. Shed/rate-limited events
        // are not remembered, so retrying a rejected ID cannot bypass either limiter.
        let now = now_secs();
        while let Some((seen_at, _)) = accepted_id_order.front() {
            if *seen_at + cfg.window_seconds > now {
                break;
            }
            if let Some((_, expired_id)) = accepted_id_order.pop_front() {
                accepted_ids.remove(&expired_id);
            }
        }
        let event_id = std::str::from_utf8(id).ok().and_then(|value| {
            if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(value.to_ascii_lowercase())
            } else {
                None
            }
        });
        if let Some(event_id) = &event_id {
            if accepted_ids.contains(event_id) {
                let (action, msg) = if shed {
                    shed_verdict(&cfg)
                } else {
                    ("accept", "")
                };
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, action, msg);
                continue;
            }
        }

        // 5a) Per-source sliding window: the same events summed over every pubkey from one
        //     address, so rotating throwaway keys does not reset the count.
        if let (Some(sk), true) = (
            &src_key,
            cfg.source_window_seconds > 0 && cfg.source_max_events > 0,
        ) {
            let sb = source_buckets.entry(sk.clone()).or_default();
            while let Some(&front) = sb.front() {
                if front + cfg.source_window_seconds <= now {
                    sb.pop_front();
                } else {
                    break;
                }
            }
            if sb.len() as u64 >= cfg.source_max_events {
                if cfg.source_ban_on_exceed {
                    banned_sources.insert(sk.clone());
                    source_buckets.remove(sk);
                    if let Some(path) = &cfg.source_ban_list_file {
                        append_ban(path, sk);
                    }
                    eprintln!("strfry-ratelimit: BANNED SOURCE {sk} (exceeded per-source rate limit; last pubkey {pubkey})");
                    respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "blocked: source is banned (rate limit exceeded)");
                } else {
                    respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "reject", "rate-limited: too many events from this address, slow down");
                }
                continue;
            }
            sb.push_back(now);
        }

        // 5) Sliding-window rate limit.
        let bucket = buckets.entry(pubkey.clone()).or_default();
        while let Some(&front) = bucket.front() {
            if front + cfg.window_seconds <= now {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() as u64 >= cfg.max_events {
            if cfg.ban_on_exceed {
                banned.insert(pubkey.clone());
                buckets.remove(&pubkey);
                if let Some(path) = &cfg.ban_list_file {
                    append_ban(path, &pubkey);
                }
                eprintln!("strfry-ratelimit: BANNED {pubkey} (exceeded rate limit)");
                respond(
                    &mut out,
                    &mut audit,
                    &cfg.audit_log_dir,
                    &ctx,
                    id,
                    "reject",
                    "blocked: pubkey is banned (rate limit exceeded)",
                );
            } else if cfg.mode_shadow {
                respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, "shadowReject", "");
            } else {
                respond(
                    &mut out,
                    &mut audit,
                    &cfg.audit_log_dir,
                    &ctx,
                    id,
                    "reject",
                    "rate-limited: too many events, slow down",
                );
            }
            continue;
        }

        bucket.push_back(now);
        // Counted against the pubkey either way; shed events are simply not stored. Remember only
        // accepted IDs: a shed event may be retried, and that retry must face both limits again.
        if !shed {
            if let Some(event_id) = event_id {
                if accepted_ids.insert(event_id.clone()) {
                    accepted_id_order.push_back((now, event_id));
                }
            }
        }
        {
            let (action, msg) = if shed {
                shed_verdict(&cfg)
            } else {
                ("accept", "")
            };
            respond(&mut out, &mut audit, &cfg.audit_log_dir, &ctx, id, action, msg);
        }

        // Periodically evict expired/empty buckets to bound memory.
        processed = processed.wrapping_add(1);
        // Keep modulo syntax compatible with the Rust 1.81 toolchain on Ubuntu 24.04.
        #[allow(clippy::manual_is_multiple_of)]
        if processed % 4096 == 0 {
            buckets.retain(|_, b| {
                while let Some(&front) = b.front() {
                    if front + cfg.window_seconds <= now {
                        b.pop_front();
                    } else {
                        break;
                    }
                }
                !b.is_empty()
            });
            source_buckets.retain(|_, b| {
                while let Some(&front) = b.front() {
                    if front + cfg.source_window_seconds <= now {
                        b.pop_front();
                    } else {
                        break;
                    }
                }
                !b.is_empty()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(rate: &str, burst: &str) -> Config {
        let map: HashMap<&str, &str> =
            [("ephemeral_rate_per_sec", rate), ("ephemeral_burst", burst)]
                .into_iter()
                .collect();
        Config::from_lookup(|k| map.get(k).map(|s| s.to_string()))
    }

    /// A ceiling whose burst can never reach 1 token would silently shed 100% of ephemeral
    /// traffic; config load must raise it to a usable depth instead.
    #[test]
    fn burst_too_small_is_raised_not_blackholed() {
        for b in ["0", "0.5", "-5"] {
            let c = cfg_with("5", b);
            assert!(
                c.ephemeral_burst >= 1.0,
                "burst {b} left unusable: {}",
                c.ephemeral_burst
            );
            let mut tb = TokenBucket::new(c.ephemeral_burst);
            assert!(
                tb.allow(c.ephemeral_rate_per_sec, c.ephemeral_burst),
                "ceiling with burst {b} never allows an event"
            );
        }
    }

    /// Unusable values must not silently read as "ceiling off" (a typo would disable the defence).
    #[test]
    fn invalid_values_are_rejected_to_zero() {
        for bad in ["5/s", "five", "nan", "inf", "-1"] {
            assert_eq!(
                cfg_with(bad, "30").ephemeral_rate_per_sec,
                0.0,
                "rate {bad}"
            );
        }
        // NaN/inf burst must not survive into the bucket clamp.
        for bad in ["nan", "inf"] {
            let c = cfg_with("5", bad);
            assert!(
                c.ephemeral_burst.is_finite(),
                "burst {bad} stayed non-finite"
            );
        }
    }

    #[test]
    fn ceiling_is_off_by_default() {
        let c = Config::from_lookup(|_| None);
        assert_eq!(c.ephemeral_rate_per_sec, 0.0);
    }

    /// Burst is spent first, then the sustained rate refills it; the cap is never exceeded.
    #[test]
    fn bucket_drains_then_refills_at_rate() {
        let (rate, burst) = (5.0, 10.0);
        let mut tb = TokenBucket::new(burst);
        let allowed = (0..50).filter(|_| tb.allow(rate, burst)).count();
        assert_eq!(allowed, 10, "burst should be exactly {burst}"); // no sleep involved: exact
        let t0 = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(600));
        let after = (0..50).filter(|_| tb.allow(rate, burst)).count();
        // Bound by what actually elapsed (sleep can overshoot on a loaded machine) rather than a
        // fixed window, so this cannot flake.
        let earned = t0.elapsed().as_secs_f64() * rate;
        assert!(
            after >= 2 && (after as f64) <= earned + 1.0,
            "refilled {after} in {:.2}s at {rate}/s (earned {earned:.1})",
            t0.elapsed().as_secs_f64()
        );
    }

    /// Refills are capped at `burst`, so a long idle period cannot bank an unbounded burst.
    #[test]
    fn idle_does_not_bank_more_than_burst() {
        let (rate, burst) = (100.0, 3.0);
        let mut tb = TokenBucket::new(burst);
        while tb.allow(rate, burst) {}
        std::thread::sleep(std::time::Duration::from_millis(200)); // would earn 20 tokens uncapped
        let after = (0..50).filter(|_| tb.allow(rate, burst)).count();
        assert!(after <= 3, "idle banked {after} tokens, cap is {burst}");
    }
}
