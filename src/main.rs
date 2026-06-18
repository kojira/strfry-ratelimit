//! strfry writePolicy plugin: per-pubkey rate limiting with optional auto-ban.
//!
//! strfry sends one JSON request per line on stdin and waits for one JSON response per line
//! on stdout. See https://github.com/hoytech/strfry/blob/master/docs/plugins.md
//!
//! Design notes:
//! - Only "accumulating" kinds are rate-limited. Ephemeral (20000-29999) is never stored and
//!   replaceable (0/3/41/10000-19999) keeps only the latest per (pubkey,kind), so neither can be
//!   used for storage abuse and both are exempt by default. Regular and addressable
//!   (30000-39999, which can accumulate via distinct d-tags) are limited.
//! - A sliding window separates one-time bursts (fixed count) from sustained spam (scales with
//!   the window), so a generous window + threshold tolerates legit bursts while catching floods.
//! - State is in-memory (the plugin is a single long-lived process). Bans optionally persist to a
//!   file so they survive restarts; delete a line and restart to unban.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Event {
    id: String,
    pubkey: String,
    kind: u64,
}

#[derive(Deserialize)]
struct Request {
    #[serde(rename = "type")]
    typ: String,
    event: Event,
    // sourceType / sourceInfo are available too (e.g. the client IP) but unused by default.
}

struct Config {
    window_seconds: u64,
    max_events: u64,
    mode_shadow: bool,    // true => shadowReject, false => reject
    ban_on_exceed: bool,
    ban_list_file: Option<String>,
    exclude_kinds: HashSet<u64>,
    exempt_ephemeral: bool,
    exempt_replaceable: bool,
    exempt_addressable: bool,
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

impl Config {
    fn from_env() -> Self {
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
        }
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

fn load_banlist(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
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

fn respond(out: &mut impl Write, id: &str, action: &str, msg: &str) {
    let v = json!({ "id": id, "action": action, "msg": msg });
    // One JSON object per line; flush so strfry sees it immediately.
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn main() {
    let cfg = Config::from_env();
    let mut banned: HashSet<String> =
        cfg.ban_list_file.as_ref().map(|p| load_banlist(p)).unwrap_or_default();
    let mut buckets: HashMap<String, VecDeque<u64>> = HashMap::new();

    eprintln!(
        "strfry-ratelimit: window={}s max={} banOnExceed={} excludeKinds={:?} exempt(eph={},repl={},addr={}) banned_loaded={}",
        cfg.window_seconds, cfg.max_events, cfg.ban_on_exceed, cfg.exclude_kinds,
        cfg.exempt_ephemeral, cfg.exempt_replaceable, cfg.exempt_addressable, banned.len()
    );

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut processed: u64 = 0;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                // Fail open: we can't safely reject something we can't parse.
                eprintln!("strfry-ratelimit: parse error: {e}");
                continue;
            }
        };

        // strfry currently only sends "new"; accept anything else untouched.
        if req.typ != "new" {
            respond(&mut stdout, &req.event.id, "accept", "");
            continue;
        }

        let pubkey = req.event.pubkey.to_ascii_lowercase();
        let kind = req.event.kind;

        // 1) Banlist: reject everything from a banned pubkey, regardless of kind.
        if !banned.is_empty() && banned.contains(&pubkey) {
            respond(&mut stdout, &req.event.id, "reject", "blocked: pubkey is banned");
            continue;
        }

        // 2) Is this kind subject to rate limiting?
        let subject = !cfg.exclude_kinds.contains(&kind)
            && !(cfg.exempt_ephemeral && is_ephemeral(kind))
            && !(cfg.exempt_replaceable && is_replaceable(kind))
            && !(cfg.exempt_addressable && is_addressable(kind));

        if !subject {
            respond(&mut stdout, &req.event.id, "accept", "");
            continue;
        }

        // 3) Sliding-window rate limit.
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
                respond(&mut stdout, &req.event.id, "reject", "blocked: pubkey is banned (rate limit exceeded)");
            } else if cfg.mode_shadow {
                respond(&mut stdout, &req.event.id, "shadowReject", "");
            } else {
                respond(&mut stdout, &req.event.id, "reject", "rate-limited: too many events, slow down");
            }
            continue;
        }

        bucket.push_back(now);
        respond(&mut stdout, &req.event.id, "accept", "");

        // Periodically evict expired/empty buckets to bound memory.
        processed = processed.wrapping_add(1);
        if processed % 4096 == 0 {
            buckets.retain(|_, b| {
                while let Some(&front) = b.front() {
                    if front + cfg.window_seconds <= now { b.pop_front(); } else { break; }
                }
                !b.is_empty()
            });
        }
    }
}
