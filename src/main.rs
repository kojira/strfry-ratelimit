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
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}
fn env_kinds(key: &str, default: &[u64]) -> HashSet<u64> {
    match std::env::var(key) {
        Ok(v) => v.split(',').filter_map(|s| s.trim().parse().ok()).collect(),
        Err(_) => default.iter().copied().collect(),
    }
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
    fn from_env() -> Self {
        let (block_singles, block_ranges) =
            parse_kind_list(&std::env::var("RL_BLOCK_KINDS").unwrap_or_default());
        Config {
            window_seconds: env_u64("RL_WINDOW_SECONDS", 60),
            max_events: env_u64("RL_MAX_EVENTS", 10),
            mode_shadow: std::env::var("RL_MODE").map(|m| m == "shadow").unwrap_or(false),
            ban_on_exceed: env_bool("RL_BAN_ON_EXCEED", false),
            ban_list_file: std::env::var("RL_BAN_LIST_FILE").ok().filter(|s| !s.is_empty()),
            exclude_kinds: env_kinds("RL_EXCLUDE_KINDS", &[7]),
            exempt_ephemeral: env_bool("RL_EXEMPT_EPHEMERAL", true),
            exempt_replaceable: env_bool("RL_EXEMPT_REPLACEABLE", true),
            exempt_addressable: env_bool("RL_EXEMPT_ADDRESSABLE", false),
            block_singles,
            block_ranges,
        }
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
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{pubkey}");
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
    let cfg = Config::from_env();
    let mut banned: HashSet<String> =
        cfg.ban_list_file.as_ref().map(|p| load_banlist(p)).unwrap_or_default();
    let mut buckets: HashMap<String, VecDeque<u64>> = HashMap::new();

    eprintln!(
        "strfry-ratelimit: window={}s max={} banOnExceed={} blockSingles={:?} blockRanges={:?} excludeKinds={:?} exempt(eph={},repl={},addr={}) banned_loaded={}",
        cfg.window_seconds, cfg.max_events, cfg.ban_on_exceed, cfg.block_singles, cfg.block_ranges,
        cfg.exclude_kinds, cfg.exempt_ephemeral, cfg.exempt_replaceable, cfg.exempt_addressable, banned.len()
    );

    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut line: Vec<u8> = Vec::with_capacity(8192);
    let mut processed: u64 = 0;

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
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
