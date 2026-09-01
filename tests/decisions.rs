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
        Plugin { child, stdin, stdout }
    }

    /// Submit one event and return the raw verdict line.
    fn send_raw(&mut self, id: &str, pubkey: &str, kind: u64) -> String {
        writeln!(
            self.stdin,
            r#"{{"type":"new","event":{{"id":"{id}","pubkey":"{pubkey}","kind":{kind}}}}}"#
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("plugin replied");
        assert!(line.contains(&format!("\"id\":\"{id}\"")), "reply was for another event: {line}");
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
    assert!(line.contains("\"action\":\"reject\""), "expected reject, got {line}");
    assert!(
        line.contains("\"msg\":\"rate-limited:"),
        "reason must start with the rate-limited: prefix, got {line}"
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
    assert!(line.contains("\"action\":\"shadowReject\""), "expected shadowReject, got {line}");
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
    assert_eq!((t.banned, t.shed, t.accept), (100, 0, 0), "banned pubkey consumed budget: {t:?}");
    let t2 = p.tally(5, PK_B, 22587);
    assert_eq!(t2.accept, 5, "banned pubkey drained the shared budget: {t2:?}");
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
    assert!(t.banned > 0, "single-source ephemeral flood was never banned: {t:?}");
    let persisted = std::fs::read_to_string(&ban_file).unwrap_or_default();
    assert!(persisted.contains(PK_A), "ban was not persisted: {persisted:?}");
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
    assert_eq!(t.blocked_kind, 100, "blocked kind was not rejected outright: {t:?}");
    let t2 = p.tally(5, PK_B, 22587);
    assert_eq!(t2.accept, 5, "blocked kinds drained the ceiling budget: {t2:?}");
}

/// Both ceilings are off unless configured, so existing deployments are unaffected.
#[test]
fn ceilings_off_by_default() {
    let mut p = Plugin::start(&[("RL_MAX_EVENTS", "1000000")]);
    let t = p.tally(300, PK_A, 22587);
    assert_eq!((t.accept, t.shed), (300, 0), "ephemeral ceiling active without config: {t:?}");
    let t2 = p.tally(300, PK_A, 1);
    assert_eq!((t2.accept, t2.shed), (300, 0), "all-kinds ceiling active without config: {t2:?}");
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
    assert!(t.shed > 150, "flood outside the ephemeral range was not capped: {t:?}");
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
    assert!(t.accept <= 3 && t.shed > 90, "ephemeral ceiling misbehaved: {t:?}");
    let t2 = p.tally(15, PK_B, 1);
    assert!(t2.accept >= 10, "flood drained the all-kinds budget: {t2:?}");
}
