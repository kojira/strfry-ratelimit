//! strfry writePolicy plugin: kind blocklist + per-pubkey rate limiting with optional auto-ban.
//!
//! strfry sends one JSON request per line on stdin and expects one JSON response per line on
//! stdout. See https://github.com/hoytech/strfry/blob/master/docs/plugins.md
//!
//! Parsing: instead of a full JSON parse we byte-scan the request line for only the four fields we
//! need (type, id, pubkey, kind). strfry's request is machine-generated, and any `"kind":` /
//! `"pubkey":` / `"id":` appearing inside a string *value* is escaped (`\"`), so these
//! key patterns never false-match content/tags. This drops the serde dependency and avoids a
//! parse+allocation per event. Whitespace after the colon is tolerated (compact or pretty JSON).
//!
//! Design:
//! - Kind blocklist (RL_BLOCK_KINDS) is checked first and drops matching kinds outright. Useful for
//!   ephemeral floods (e.g. relayed WebRTC signaling) that per-pubkey rate limiting cannot catch
//!   because each event uses a throwaway pubkey.
//! - Rate limiting applies only to "accumulating" kinds. Ephemeral (20000-29999) and replaceable
//!   (0/3/41/10000-19999) cannot be used for storage abuse and are exempt by default; addressable
//!   (30000-39999) is opt-in. A sliding window separates legit bursts from sustained spam. State is
//!   in-memory (single long-lived process); bans optionally persist to a file to survive restarts.

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
    /// Relay-wide ceiling on ephemeral events (kinds 20000-29999), in events per second.
    /// 0 disables it. Unlike the per-pubkey limit this is a single global budget, which is what
    /// catches a *distributed* flood: hundreds of pubkeys/IPs each sending a modest rate sum to a
    /// firehose that no per-sender limit can see. It is also kind-agnostic, so an attacker that
    /// switches to a different ephemeral kind is still capped.
    ephemeral_rate_per_sec: f64,
    /// Bucket depth for the above — how big an instantaneous burst is allowed through before the
    /// sustained rate applies (e.g. several clients starting a call at once).
    ephemeral_burst: f64,
}

/// Token bucket for the relay-wide ephemeral ceiling. Refills at `rate` tokens/sec up to
/// `burst`; each ephemeral event costs one token. Empty bucket => shed the event.
struct TokenBucket {
    tokens: f64,
    last: f64,
}

impl TokenBucket {
    fn new(burst: f64) -> Self {
        TokenBucket { tokens: burst, last: now_millis() }
    }
    /// Try to spend one token, refilling first. Returns false when the budget is exhausted.
    fn allow(&mut self, rate: f64, burst: f64) -> bool {
        let now = now_millis();
        // Guard against a non-monotonic clock: never refill on a backwards jump.
        let elapsed = ((now - self.last) / 1000.0).max(0.0);
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
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(d)
        };
        let kinds_of = |k: &str, d: &[u64]| -> HashSet<u64> {
            get(k)
                .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
                .unwrap_or_else(|| d.iter().copied().collect())
        };
        let (block_singles, block_ranges) = parse_kind_list(&get("block_kinds").unwrap_or_default());
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
            ephemeral_rate_per_sec: get("ephemeral_rate_per_sec")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0.0),
            ephemeral_burst: get("ephemeral_burst")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0.0),
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
        self.block_singles.iter().any(|&k| k == kind)
            || self.block_ranges.iter().any(|&(lo, hi)| lo <= kind && kind <= hi)
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Wall-clock milliseconds as f64, for sub-second token-bucket refills.
fn now_millis() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0)
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
fn append_ban(path: &str, pubkey: &str) {
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{pubkey}");
        }
        Err(e) => eprintln!("strfry-ratelimit: failed to persist ban for {pubkey} to {path}: {e}"),
    }
}

/// Write one response line. `id` is 64-char hex and `action`/`msg` are fixed ASCII literals, so no
/// JSON string escaping is needed.
fn respond(out: &mut impl Write, id: &[u8], action: &str, msg: &str) {
    let _ = out.write_all(b"{\"id\":\"");
    let _ = out.write_all(id);
    let _ = out.write_all(b"\",\"action\":\"");
    let _ = out.write_all(action.as_bytes());
    let _ = out.write_all(b"\",\"msg\":\"");
    let _ = out.write_all(msg.as_bytes());
    let _ = out.write_all(b"\"}\n");
    let _ = out.flush();
}

fn main() {
    // Config from a file if RL_CONFIG_FILE is set (hot-reloaded on mtime change), else from
    // environment variables (read once at startup — fully backward compatible).
    let cfg_path = std::env::var("RL_CONFIG_FILE").ok().filter(|s| !s.is_empty());
    let mut cfg = match &cfg_path {
        Some(p) => Config::from_file(p).unwrap_or_else(|| {
            eprintln!("strfry-ratelimit: config file {p} unreadable/empty at startup; using defaults");
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
    // Relay-wide ephemeral budget. Sized from the current config; a hot-reload that raises the
    // burst is picked up by allow()'s clamp on the next event.
    let mut eph_bucket = TokenBucket::new(cfg.ephemeral_burst);
    let mut eph_shed: u64 = 0;

    eprintln!(
        "strfry-ratelimit: source={} window={}s max={} banOnExceed={} blockSingles={:?} blockRanges={:?} excludeKinds={:?} exempt(eph={},repl={},addr={}) ephemeralCeiling={} banned_loaded={}",
        cfg_path.as_deref().unwrap_or("env"), cfg.window_seconds, cfg.max_events, cfg.ban_on_exceed,
        cfg.block_singles, cfg.block_ranges, cfg.exclude_kinds, cfg.exempt_ephemeral,
        cfg.exempt_replaceable, cfg.exempt_addressable,
        if cfg.ephemeral_rate_per_sec > 0.0 {
            format!("{}/s burst {}", cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst)
        } else {
            "off".to_string()
        },
        banned.len()
    );

    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut line: Vec<u8> = Vec::with_capacity(8192);
    let mut processed: u64 = 0;
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
                        eprintln!("strfry-ratelimit: reloaded config from {p}");
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
                respond(&mut out, id, "accept", "");
                continue;
            }
        }

        let kind = scan_u64(buf, b"\"kind\":");

        // 1) Kind blocklist — cheap, drops floods outright before we extract pubkey or touch state.
        if let Some(k) = kind {
            if cfg.is_blocked(k) {
                respond(&mut out, id, "reject", "blocked: kind not accepted here");
                continue;
            }
        }

        // 1b) Relay-wide ephemeral ceiling. Deliberately BEFORE pubkey extraction and the
        //     per-pubkey limit: a distributed flood spreads itself thin across many pubkeys, so
        //     only a global budget can see it. Kind-agnostic, so switching ephemeral kinds does
        //     not evade it.
        if cfg.ephemeral_rate_per_sec > 0.0 {
            if let Some(k) = kind {
                if is_ephemeral(k) && !eph_bucket.allow(cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst) {
                    eph_shed = eph_shed.wrapping_add(1);
                    // Log once per 1000 shed events so a sustained flood is visible without
                    // reproducing the log-spam that the flood itself causes.
                    if eph_shed % 1000 == 1 {
                        eprintln!(
                            "strfry-ratelimit: ephemeral ceiling active ({}/s burst {}), shed {} events so far (latest kind {})",
                            cfg.ephemeral_rate_per_sec, cfg.ephemeral_burst, eph_shed, k
                        );
                    }
                    // shadowReject: the sender is told OK, but nothing is stored or broadcast.
                    // A flood source gets no signal to switch tactics, and a legitimate client
                    // caught in the overflow is not shown a confusing error.
                    respond(&mut out, id, "shadowReject", "");
                    continue;
                }
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
                respond(&mut out, id, "reject", "blocked: pubkey is banned");
                continue;
            }
        }

        // Rate limiting needs a readable kind and pubkey; otherwise accept (fail open).
        let (kind, pubkey) = match (kind, pubkey) {
            (Some(k), Some(pk)) => (k, pk),
            _ => {
                respond(&mut out, id, "accept", "");
                continue;
            }
        };

        // 3) Is this kind subject to rate limiting?
        let subject = !cfg.exclude_kinds.contains(&kind)
            && !(cfg.exempt_ephemeral && is_ephemeral(kind))
            && !(cfg.exempt_replaceable && is_replaceable(kind))
            && !(cfg.exempt_addressable && is_addressable(kind));
        if !subject {
            respond(&mut out, id, "accept", "");
            continue;
        }

        // 4) Sliding-window rate limit.
        let now = now_secs();
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
                respond(&mut out, id, "reject", "blocked: pubkey is banned (rate limit exceeded)");
            } else if cfg.mode_shadow {
                respond(&mut out, id, "shadowReject", "");
            } else {
                respond(&mut out, id, "reject", "rate-limited: too many events, slow down");
            }
            continue;
        }

        bucket.push_back(now);
        respond(&mut out, id, "accept", "");

        // Periodically evict expired/empty buckets to bound memory.
        processed = processed.wrapping_add(1);
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
        }
    }
}
