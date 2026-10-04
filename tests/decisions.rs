//! End-to-end tests: spawn the real binary and drive it the way strfry does (one JSON request per
//! line on stdin, one verdict per line on stdout).
//!
//! These cover the decision *ordering* in `main` — the ceilings relative to the kind blocklist,
//! the banlist, and the per-pubkey limiter — which unit tests on `Config`/`TokenBucket` cannot
//! reach.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Plugin {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// A verdict, classified by what produced it.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Verdict {
    Accept,
    /// Shed by a relay-wide ceiling (either mode).
    Shed,
    Banned,
    BlockedKind,
    /// Per-pubkey limiter.
    RateLimited,
    Other,
}

#[derive(Default, Debug)]
struct Tally {
    accept: usize,
    shed: usize,
    banned: usize,
    blocked_kind: usize,
    rate_limited: usize,
    other: usize,
}

impl Plugin {
    fn start(env: &[(&str, &str)]) -> Plugin {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_strfry-ratelimit"));
        cmd.env_clear().env("PATH", "/usr/bin:/bin");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn plugin");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Plugin {
            child,
            stdin,
            stdout,
        }
    }

    /// Submit one event and return the raw verdict line.
    fn send_raw(&mut self, id: &str, pubkey: &str, kind: u64) -> String {
        self.send_raw_from(id, pubkey, kind, "")
    }

    fn send_raw_from(&mut self, id: &str, pubkey: &str, kind: u64, source: &str) -> String {
        writeln!(
            self.stdin,
            r#"{{"type":"new","sourceType":"IP4","sourceInfo":"{source}","event":{{"id":"{id}","pubkey":"{pubkey}","kind":{kind}}}}}"#
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("plugin replied");
        assert!(
            line.contains(&format!("\"id\":\"{id}\"")),
            "reply was for another event: {line}"
        );
        line
    }

    fn classify(line: &str) -> Verdict {
        let action = ["shadowReject", "accept", "reject"]
            .into_iter()
            .find(|a| line.contains(&format!("\"action\":\"{a}\"")))
            .unwrap_or_else(|| panic!("no action in reply: {line}"));
        let msg = line
            .split("\"msg\":\"")
            .nth(1)
            .and_then(|m| m.split('"').next())
            .unwrap_or("");
        match action {
            "accept" => Verdict::Accept,
            "shadowReject" => Verdict::Shed,
            _ if msg.starts_with("rate-limited: relay ceiling") => Verdict::Shed,
            _ if msg.starts_with("blocked: pubkey is banned") => Verdict::Banned,
            _ if msg.starts_with("blocked: kind") => Verdict::BlockedKind,
            _ if msg.starts_with("rate-limited:") => Verdict::RateLimited,
            _ => Verdict::Other,
        }
    }

    fn send(&mut self, id: &str, pubkey: &str, kind: u64) -> Verdict {
        Self::classify(&self.send_raw(id, pubkey, kind))
    }

    fn send_from(&mut self, id: &str, pubkey: &str, kind: u64, source: &str) -> Verdict {
        Self::classify(&self.send_raw_from(id, pubkey, kind, source))
    }


    fn send_at(&mut self, id: &str, pubkey: &str, kind: u64, created_at: u64) -> Verdict {
        writeln!(
            self.stdin,
            r#"{{"type":"new","sourceType":"IP4","sourceInfo":"","event":{{"id":"{id}","pubkey":"{pubkey}","kind":{kind},"created_at":{created_at}}}}}"#
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("plugin replied");
        Self::classify(&line)
    }

    fn tally(&mut self, n: usize, pubkey: &str, kind: u64) -> Tally {
        let mut t = Tally::default();
        for i in 0..n {
            match self.send(&format!("{i:064x}"), pubkey, kind) {
                Verdict::Accept => t.accept += 1,
                Verdict::Shed => t.shed += 1,
                Verdict::Banned => t.banned += 1,
                Verdict::BlockedKind => t.blocked_kind += 1,
                Verdict::RateLimited => t.rate_limited += 1,
                Verdict::Other => t.other += 1,
            }
        }
        t
    }

    /// One event per distinct pubkey — the shape a distributed flood takes.
    fn tally_distributed(&mut self, n: usize, kind: u64) -> Tally {
        let mut t = Tally::default();
        for i in 0..n {
            match self.send(&format!("{i:064x}"), &format!("{i:064x}"), kind) {
                Verdict::Accept => t.accept += 1,
                Verdict::Shed => t.shed += 1,
                Verdict::Banned => t.banned += 1,
                Verdict::BlockedKind => t.blocked_kind += 1,
                Verdict::RateLimited => t.rate_limited += 1,
                Verdict::Other => t.other += 1,
            }
        }
        t
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const PK_A: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const PK_B: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

#[test]
fn blocks_ephemeral_only_from_configured_sources() {
    let mut p = Plugin::start(&[
        (
            "RL_BLOCK_EPHEMERAL_SOURCES",
            "149.28.29.200, 2001:19f0:7002:191:0:bad:c0de:1337",
        ),
        ("RL_BLOCK_SOURCE_MODE", "shadow"),
        ("RL_MAX_EVENTS", "1000000"),
    ]);

    let blocked_v4 = p.send_raw_from("01", PK_A, 27889, "149.28.29.200");
    assert!(
        blocked_v4.contains("\"action\":\"shadowReject\""),
        "{blocked_v4}"
    );
    let blocked_v6 = p.send_raw_from("02", PK_A, 22587, "2001:19f0:7002:191:0:bad:c0de:1337");
    assert!(
        blocked_v6.contains("\"action\":\"shadowReject\""),
        "{blocked_v6}"
    );

    assert_eq!(
        p.send_from("03", PK_A, 27889, "203.0.113.10"),
        Verdict::Accept
    );
    assert_eq!(p.send_from("04", PK_A, 1, "149.28.29.200"), Verdict::Accept);
    assert_eq!(p.send_from("05", PK_A, 27889, ""), Verdict::Accept);
}

#[test]
fn blocked_source_defaults_to_explicit_reject() {
    let mut p = Plugin::start(&[("RL_BLOCK_EPHEMERAL_SOURCES", "149.28.29.200")]);
    let line = p.send_raw_from("01", PK_A, 27889, "149.28.29.200");
    assert!(line.contains("\"action\":\"reject\""), "{line}");
    assert!(
        line.contains("blocked: ephemeral events from this source"),
        "{line}"
    );
}

#[test]
fn duplicate_accepted_event_ids_count_only_once() {
    let mut p = Plugin::start(&[("RL_MAX_EVENTS", "2")]);
    let first = format!("{:064x}", 1);
    let second = format!("{:064x}", 2);
    let third = format!("{:064x}", 3);

    assert_eq!(p.send(&first, PK_A, 1), Verdict::Accept);
    assert_eq!(p.send(&first, PK_A, 1), Verdict::Accept);
    assert_eq!(
        p.send_from(&first, PK_A, 1, "149.28.29.200"),
        Verdict::Accept
    );
    assert_eq!(p.send(&second, PK_A, 1), Verdict::Accept);
    assert_eq!(p.send(&third, PK_A, 1), Verdict::RateLimited);
}

#[test]
fn configured_sources_are_exempt_only_from_per_pubkey_limit() {
    let mut p = Plugin::start(&[
        (
            "RL_EXEMPT_RATE_LIMIT_SOURCES",
            "149.28.29.200, 2001:DB8::10",
        ),
        ("RL_MAX_EVENTS", "2"),
    ]);

    for i in 0..20 {
        assert_eq!(
            p.send_from(&format!("{i:064x}"), PK_A, 1, "149.28.29.200"),
            Verdict::Accept
        );
    }
    // Matching is case-insensitive (relevant for URL sourceInfo; harmless for IP literals).
    assert_eq!(
        p.send_from(&format!("{:064x}", 100), PK_A, 1, "2001:db8::10"),
        Verdict::Accept
    );
    assert_eq!(p.send(&format!("{:064x}", 101), PK_A, 1), Verdict::Accept);
    assert_eq!(p.send(&format!("{:064x}", 102), PK_A, 1), Verdict::Accept);
    assert_eq!(
        p.send(&format!("{:064x}", 103), PK_A, 1),
        Verdict::RateLimited
    );
}

#[test]
fn exempt_rate_limit_source_still_consumes_global_ceiling() {
    let mut p = Plugin::start(&[
        ("RL_EXEMPT_RATE_LIMIT_SOURCES", "149.28.29.200"),
        ("RL_TOTAL_RATE_PER_SEC", "1"),
        ("RL_TOTAL_BURST", "1"),
    ]);
    assert_eq!(
        p.send_from(&format!("{:064x}", 1), PK_A, 1, "149.28.29.200"),
        Verdict::Accept
    );
    assert_eq!(
        p.send_from(&format!("{:064x}", 2), PK_A, 1, "149.28.29.200"),
        Verdict::Shed
    );
}

#[test]
fn exempt_rate_limit_source_does_not_bypass_existing_ban() {
    let dir = std::env::temp_dir().join(format!("srl-exempt-ban-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban_file = dir.join("bans.txt");
    std::fs::write(&ban_file, format!("{PK_A}\n")).unwrap();
    let mut p = Plugin::start(&[
        ("RL_EXEMPT_RATE_LIMIT_SOURCES", "149.28.29.200"),
        ("RL_BAN_LIST_FILE", ban_file.to_str().unwrap()),
    ]);
    assert_eq!(
        p.send_from(&format!("{:064x}", 1), PK_A, 1, "149.28.29.200"),
        Verdict::Banned
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shed_event_id_is_not_cached_as_accepted() {
    let mut p = Plugin::start(&[
        ("RL_TOTAL_RATE_PER_SEC", "1"),
        ("RL_TOTAL_BURST", "1"),
        ("RL_MAX_EVENTS", "2"),
    ]);
    let accepted = format!("{:064x}", 1);
    let shed = format!("{:064x}", 2);
    assert_eq!(p.send(&accepted, PK_A, 1), Verdict::Accept);
    assert_eq!(p.send(&shed, PK_A, 1), Verdict::Shed);
    assert_eq!(p.send(&shed, PK_A, 1), Verdict::RateLimited);
}

/// The ceiling sheds a distributed flood that no per-pubkey limit could see.
#[test]
fn ceiling_sheds_distributed_flood() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "5"),
        ("RL_EPHEMERAL_BURST", "10"),
    ]);
    let t = p.tally_distributed(200, 22587);
    assert!(t.shed > 150, "flood was not shed: {t:?}");
    assert!(t.accept <= 12, "let through more than the burst: {t:?}");
    assert_eq!(t.other, 0, "unexpected verdicts: {t:?}");
}

/// By default a shed event is a `reject` whose reason carries the `rate-limited:` prefix —
/// the signal cooperative clients (strfry's own limiter, Trystero >= 0.25.4) back off on.
#[test]
fn ceiling_reject_reason_lets_clients_back_off() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "1"),
    ]);
    p.send_raw("00", PK_A, 22587); // spend the single token
    let line = p.send_raw("01", PK_A, 22587);
    assert!(
        line.contains("\"action\":\"reject\""),
        "expected reject, got {line}"
    );
    assert!(
        line.contains("\"msg\":\"rate-limited:"),
        "reason must start with the rate-limited: prefix, got {line}"
    );
}

/// The all-kinds ceiling uses the same default verdict (guards a site-specific regression).
#[test]
fn total_ceiling_reject_reason_lets_clients_back_off() {
    let mut p = Plugin::start(&[
        ("RL_TOTAL_RATE_PER_SEC", "1"),
        ("RL_TOTAL_BURST", "1"),
        ("RL_MAX_EVENTS", "1000000"),
    ]);
    p.send_raw("00", PK_A, 1);
    let line = p.send_raw("01", PK_A, 1);
    assert!(
        line.contains("\"action\":\"reject\""),
        "expected reject, got {line}"
    );
    assert!(
        line.contains("\"msg\":\"rate-limited:"),
        "missing rate-limited: prefix: {line}"
    );
}

/// `ceiling_mode = shadow` keeps the old silent behaviour for sources you don't want to tip off.
#[test]
fn ceiling_shadow_mode_answers_shadow_reject() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "1"),
        ("RL_CEILING_MODE", "shadow"),
    ]);
    p.send_raw("00", PK_A, 22587);
    let line = p.send_raw("01", PK_A, 22587);
    assert!(
        line.contains("\"action\":\"shadowReject\""),
        "expected shadowReject, got {line}"
    );
}

/// Non-ephemeral traffic must be untouched by the ephemeral ceiling, even mid-flood.
#[test]
fn ceiling_does_not_touch_normal_kinds() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "1"),
        ("RL_MAX_EVENTS", "100000"),
    ]);
    p.tally(100, PK_A, 22587); // drain the budget
    let t = p.tally(20, PK_B, 1);
    assert_eq!(t.accept, 20, "kind 1 was affected by the ceiling: {t:?}");
}

/// Regression (H2): a banned pubkey must be rejected *before* it can drain the shared budget.
#[test]
fn banned_pubkey_does_not_drain_budget() {
    let dir = std::env::temp_dir().join(format!("srl-ban-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban_file = dir.join("bans.txt");
    std::fs::write(&ban_file, format!("{PK_A}\n")).unwrap();

    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "5"),
        ("RL_BAN_LIST_FILE", ban_file.to_str().unwrap()),
    ]);
    let t = p.tally(100, PK_A, 22587);
    assert_eq!(
        (t.banned, t.shed, t.accept),
        (100, 0, 0),
        "banned pubkey consumed budget: {t:?}"
    );
    let t2 = p.tally(5, PK_B, 22587);
    assert_eq!(
        t2.accept, 5,
        "banned pubkey drained the shared budget: {t2:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression (H4): with ephemerals subject to the per-pubkey limiter, a shed event must still
/// count against the window so a single-source flood is auto-banned.
#[test]
fn shed_events_still_trigger_auto_ban() {
    let dir = std::env::temp_dir().join(format!("srl-autoban-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban_file = dir.join("bans.txt");

    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "2"),
        ("RL_EXEMPT_EPHEMERAL", "false"),
        ("RL_BAN_ON_EXCEED", "true"),
        ("RL_MAX_EVENTS", "10"),
        ("RL_BAN_LIST_FILE", ban_file.to_str().unwrap()),
    ]);
    let t = p.tally(60, PK_A, 22587);
    assert!(
        t.banned > 0,
        "single-source ephemeral flood was never banned: {t:?}"
    );
    let persisted = std::fs::read_to_string(&ban_file).unwrap_or_default();
    assert!(
        persisted.contains(PK_A),
        "ban was not persisted: {persisted:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Blocked kinds are rejected before the ceiling, so they must not consume the budget.
#[test]
fn blocked_kinds_do_not_drain_budget() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "5"),
        ("RL_BLOCK_KINDS", "20001"),
    ]);
    let t = p.tally(100, PK_A, 20001);
    assert_eq!(
        t.blocked_kind, 100,
        "blocked kind was not rejected outright: {t:?}"
    );
    let t2 = p.tally(5, PK_B, 22587);
    assert_eq!(
        t2.accept, 5,
        "blocked kinds drained the ceiling budget: {t2:?}"
    );
}

/// Both ceilings are off unless configured, so existing deployments are unaffected.
#[test]
fn ceilings_off_by_default() {
    let mut p = Plugin::start(&[("RL_MAX_EVENTS", "1000000")]);
    let t = p.tally(300, PK_A, 22587);
    assert_eq!(
        (t.accept, t.shed),
        (300, 0),
        "ephemeral ceiling active without config: {t:?}"
    );
    let t2 = p.tally(300, PK_A, 1);
    assert_eq!(
        (t2.accept, t2.shed),
        (300, 0),
        "all-kinds ceiling active without config: {t2:?}"
    );
}

/// The all-kinds ceiling catches a distributed flood that left the ephemeral range.
#[test]
fn total_ceiling_catches_flood_outside_ephemeral_range() {
    let mut p = Plugin::start(&[
        ("RL_TOTAL_RATE_PER_SEC", "5"),
        ("RL_TOTAL_BURST", "10"),
        ("RL_MAX_EVENTS", "1000000"),
    ]);
    let t = p.tally_distributed(200, 1);
    assert!(
        t.shed > 150,
        "flood outside the ephemeral range was not capped: {t:?}"
    );
    assert!(t.accept <= 12, "let through more than the burst: {t:?}");
}

/// An event shed by the ephemeral ceiling must not also be charged to the all-kinds budget.
#[test]
fn ephemeral_shed_does_not_charge_total_budget() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "2"),
        ("RL_TOTAL_RATE_PER_SEC", "1"),
        ("RL_TOTAL_BURST", "20"),
        ("RL_MAX_EVENTS", "1000000"),
    ]);
    let t = p.tally(100, PK_A, 22587);
    assert!(
        t.accept <= 3 && t.shed > 90,
        "ephemeral ceiling misbehaved: {t:?}"
    );
    let t2 = p.tally(15, PK_B, 1);
    assert!(
        t2.accept >= 10,
        "flood drained the all-kinds budget: {t2:?}"
    );
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn backlog_sync_of_old_events_does_not_ban_author() {
    let mut p = Plugin::start(&[
        ("RL_WINDOW_SECONDS", "60"),
        ("RL_MAX_EVENTS", "3"),
        ("RL_BAN_ON_EXCEED", "true"),
        ("RL_COUNT_MAX_AGE_SECONDS", "600"),
    ]);
    let pk = "a".repeat(64);
    let old = unix_now() - 90 * 86400;
    for i in 0..50 {
        assert_eq!(p.send_at(&format!("{i:064x}"), &pk, 1, old), Verdict::Accept);
    }
    // Fresh posts are still limited normally.
    let now = unix_now();
    let mut v = Vec::new();
    for i in 100..105 {
        v.push(p.send_at(&format!("{i:064x}"), &pk, 1, now));
    }
    assert_eq!(&v[..3], &[Verdict::Accept; 3]);
    assert_eq!(v[3], Verdict::Banned);
}

#[test]
fn count_max_age_off_by_default_counts_old_events() {
    let mut p = Plugin::start(&[
        ("RL_WINDOW_SECONDS", "60"),
        ("RL_MAX_EVENTS", "3"),
    ]);
    let pk = "b".repeat(64);
    let old = unix_now() - 90 * 86400;
    let v: Vec<_> = (0..4)
        .map(|i| p.send_at(&format!("{i:064x}"), &pk, 1, old))
        .collect();
    assert_eq!(v[3], Verdict::RateLimited);
}

#[test]
fn banned_author_old_events_still_rejected() {
    let dir = std::env::temp_dir().join(format!("rl-age-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban = dir.join("ban.txt");
    let pk = "c".repeat(64);
    std::fs::write(&ban, format!("{pk}\n")).unwrap();
    let mut p = Plugin::start(&[
        ("RL_BAN_LIST_FILE", ban.to_str().unwrap()),
        ("RL_COUNT_MAX_AGE_SECONDS", "600"),
    ]);
    assert_eq!(p.send_at(&"1".repeat(64), &pk, 1, unix_now() - 86400), Verdict::Banned);
}

#[test]
fn audit_log_records_source_and_verdict() {
    let dir = std::env::temp_dir().join(format!("rl-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ban = dir.join("ban.txt");
    let bad = "d".repeat(64);
    std::fs::write(&ban, format!("{bad}\n")).unwrap();
    let mut p = Plugin::start(&[
        ("RL_AUDIT_LOG_DIR", dir.to_str().unwrap()),
        ("RL_BAN_LIST_FILE", ban.to_str().unwrap()),
    ]);
    assert_eq!(p.send_from(&"1".repeat(64), &"e".repeat(64), 1, "203.0.113.7"), Verdict::Accept);
    assert_eq!(p.send_from(&"2".repeat(64), &bad, 1, "2001:db8::9"), Verdict::Banned);
    drop(p);
    let files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .collect();
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(files[0].path()).unwrap();
    let lines: Vec<Vec<&str>> = text.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0][1], "203.0.113.7");
    assert_eq!(lines[0][2], "1".repeat(64));
    assert_eq!(lines[0][3], "e".repeat(64));
    assert_eq!(lines[0][4], "1");
    assert_eq!(lines[0][7], "accept");
    assert_eq!(lines[1][1], "2001:db8::9");
    assert_eq!(lines[1][7], "reject");
    assert!(lines[1][8].starts_with("blocked: pubkey is banned"));
}

impl Plugin {
    fn send_30078(&mut self, id: &str, pubkey: &str, d: &str, content_len: usize) -> String {
        let content = "A".repeat(content_len);
        writeln!(
            self.stdin,
            r#"{{"type":"new","sourceType":"IP4","sourceInfo":"198.51.100.1","event":{{"id":"{id}","pubkey":"{pubkey}","kind":30078,"created_at":1,"tags":[["d","{d}"]],"content":"{content}"}}}}"#
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("plugin replied");
        line
    }
}

#[test]
fn file_chunk_ban_bans_uploader_only_for_large_file_dtags() {
    let dir = std::env::temp_dir().join(format!("rl-fc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ban = dir.join("ban.txt");
    std::fs::write(&ban, "").unwrap();
    let mut p = Plugin::start(&[
        ("RL_BAN_LIST_FILE", ban.to_str().unwrap()),
        ("RL_FILE_CHUNK_ACTION", "ban"),
    ]);
    let app = "1".repeat(64);
    // Normal app data, small file_ tag, and non-matching names are untouched.
    assert!(p.send_30078(&"a".repeat(64), &app, "nostr_river_flowmeter_12", 40960).contains("\"accept\""));
    assert!(p.send_30078(&"b".repeat(64), &app, "file_abc_1", 100).contains("\"accept\""));
    assert!(p.send_30078(&"c".repeat(64), &app, "file_abc_x", 40960).contains("\"accept\""));
    assert!(p.send_30078(&"d".repeat(64), &app, "myfile_abc_1", 40960).contains("\"accept\""));
    let up = "2".repeat(64);
    let r = p.send_30078(&"e".repeat(64), &up, "file_p7yrtkvlm0q_1701", 40960);
    assert!(r.contains("\"reject\"") && r.contains("banned"), "{r}");
    assert_eq!(p.send(&"f".repeat(64), &up, 1), Verdict::Banned);
    drop(p);
    let saved = std::fs::read_to_string(&ban).unwrap();
    assert!(saved.contains(&up) && !saved.contains(&app));
}

#[test]
fn file_chunk_ignore_shadow_rejects_without_ban() {
    let mut p = Plugin::start(&[("RL_FILE_CHUNK_ACTION", "ignore")]);
    let up = "3".repeat(64);
    let r = p.send_30078(&"a".repeat(64), &up, "file_kc23qmd9huf_0", 40960);
    assert!(r.contains("\"shadowReject\""), "{r}");
    assert_eq!(p.send(&"b".repeat(64), &up, 1), Verdict::Accept);
}

#[test]
fn file_chunk_off_by_default() {
    let mut p = Plugin::start(&[]);
    let r = p.send_30078(&"a".repeat(64), &"4".repeat(64), "file_kc23qmd9huf_0", 40960);
    assert!(r.contains("\"accept\""), "{r}");
}

#[test]
fn source_limit_bans_key_rotating_sender_and_all_its_kinds() {
    let dir = std::env::temp_dir().join(format!("rl-srcban-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban = dir.join("banned-sources.txt");
    let _ = std::fs::remove_file(&ban);
    let mut p = Plugin::start(&[
        ("RL_MAX_EVENTS", "1000"),
        ("RL_WINDOW_SECONDS", "180"),
        ("RL_SOURCE_WINDOW_SECONDS", "600"),
        ("RL_SOURCE_MAX_EVENTS", "5"),
        ("RL_SOURCE_BAN_ON_EXCEED", "true"),
        ("RL_SOURCE_BAN_LIST_FILE", ban.to_str().unwrap()),
        ("RL_EXEMPT_RATE_LIMIT_SOURCES", "149.28.29.200"),
    ]);
    // Five fresh pubkeys within one IPv6 /64 (different interface IDs) are all accepted...
    for i in 0..5 {
        let src = format!("240d:1a:574:a900::{:x}", i + 1);
        assert_eq!(p.send_from(&format!("{i:064x}"), &format!("{:064x}", 100 + i), 1, &src), Verdict::Accept);
    }
    // ...the sixth, with yet another new key, bans the /64.
    let line = p.send_raw_from(&format!("{:064x}", 5), &format!("{:064x}", 200), 1, "240d:1a:574:a900:9506:b091:9ce1:d13e");
    assert!(line.contains("blocked: source is banned"), "{line}");
    // Now every kind from that /64 is rejected, including exempt ones (ephemeral, reaction).
    for (i, k) in [20000u64, 7, 0].iter().enumerate() {
        let line = p.send_raw_from(&format!("{:064x}", 10 + i), &format!("{:064x}", 300 + i), *k, "240d:1a:574:a900::99");
        assert!(line.contains("blocked: source is banned"), "kind {k}: {line}");
    }
    // Other addresses, a different /64 and the exempt forwarder are unaffected.
    assert_eq!(p.send_from(&format!("{:064x}", 20), PK_A, 1, "240d:1a:574:a901::1"), Verdict::Accept);
    assert_eq!(p.send_from(&format!("{:064x}", 21), PK_A, 1, "203.0.113.5"), Verdict::Accept);
    assert_eq!(p.send_from(&format!("{:064x}", 22), PK_B, 1, "149.28.29.200"), Verdict::Accept);
    // Persisted as the /64.
    assert_eq!(std::fs::read_to_string(&ban).unwrap().trim(), "240d:1a:574:a900::/64");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn source_limit_counts_only_subject_events_and_skips_exempt_forwarder() {
    let mut p = Plugin::start(&[
        ("RL_MAX_EVENTS", "1000"),
        ("RL_SOURCE_WINDOW_SECONDS", "600"),
        ("RL_SOURCE_MAX_EVENTS", "3"),
        ("RL_SOURCE_BAN_ON_EXCEED", "true"),
        ("RL_EXEMPT_RATE_LIMIT_SOURCES", "149.28.29.200"),
    ]);
    // Ephemeral, reactions and replaceable events do not count toward the source window.
    for (i, k) in [20000u64, 20001, 7, 0, 3, 10002, 20000, 7].iter().enumerate() {
        assert_eq!(p.send_from(&format!("{i:064x}"), PK_A, *k, "198.51.100.7"), Verdict::Accept);
    }
    // A trusted forwarder is never source-limited.
    for i in 0..10 {
        assert_eq!(p.send_from(&format!("{:064x}", 100 + i), PK_B, 1, "149.28.29.200"), Verdict::Accept);
    }
    // Three counted events pass, the fourth exceeds.
    for i in 0..3 {
        assert_eq!(p.send_from(&format!("{:064x}", 200 + i), PK_A, 1, "198.51.100.7"), Verdict::Accept);
    }
    let line = p.send_raw_from(&format!("{:064x}", 300), PK_A, 1, "198.51.100.7");
    assert!(line.contains("blocked: source is banned"), "{line}");
}

#[test]
fn source_limit_without_ban_only_rate_limits() {
    let mut p = Plugin::start(&[
        ("RL_MAX_EVENTS", "1000"),
        ("RL_SOURCE_WINDOW_SECONDS", "600"),
        ("RL_SOURCE_MAX_EVENTS", "2"),
    ]);
    for i in 0..2 {
        assert_eq!(p.send_from(&format!("{i:064x}"), PK_A, 1, "198.51.100.8"), Verdict::Accept);
    }
    assert_eq!(p.send_from(&format!("{:064x}", 2), PK_B, 1, "198.51.100.8"), Verdict::RateLimited);
    // Not banned: an exempt kind from the same address still passes.
    assert_eq!(p.send_from(&format!("{:064x}", 3), PK_B, 20000, "198.51.100.8"), Verdict::Accept);
}

#[test]
fn source_limit_off_by_default() {
    let mut p = Plugin::start(&[("RL_MAX_EVENTS", "1000")]);
    for i in 0..50 {
        assert_eq!(p.send_from(&format!("{i:064x}"), &format!("{:064x}", i + 1), 1, "198.51.100.9"), Verdict::Accept);
    }
}

#[test]
fn source_banlist_file_is_loaded_and_hot_unbanned() {
    let dir = std::env::temp_dir().join(format!("rl-srcload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ban = dir.join("banned-sources.txt");
    std::fs::write(&ban, "# comment\n240d:1a:574:a900::/64\n192.0.2.1\n").unwrap();
    let mut p = Plugin::start(&[("RL_SOURCE_BAN_LIST_FILE", ban.to_str().unwrap())]);
    let l = p.send_raw_from(&format!("{:064x}", 1), PK_A, 1, "240d:1a:574:a900:1234::5");
    assert!(l.contains("blocked: source is banned"), "{l}");
    let l = p.send_raw_from(&format!("{:064x}", 2), PK_A, 1, "192.0.2.1");
    assert!(l.contains("blocked: source is banned"), "{l}");
    assert_eq!(p.send_from(&format!("{:064x}", 3), PK_A, 1, "192.0.2.2"), Verdict::Accept);
    // Unban by removing the line; reload is mtime-driven and checked every 64 events.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&ban, "192.0.2.1\n").unwrap();
    for i in 0..70 {
        p.send_raw_from(&format!("{:064x}", 100 + i), PK_B, 1, "203.0.113.77");
    }
    assert_eq!(p.send_from(&format!("{:064x}", 9), PK_A, 1, "240d:1a:574:a900:1234::5"), Verdict::Accept);
    let _ = std::fs::remove_dir_all(&dir);
}
