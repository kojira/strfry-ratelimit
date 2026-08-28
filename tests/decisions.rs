//! End-to-end tests: spawn the real binary and drive it the way strfry does (one JSON request per
//! line on stdin, one verdict per line on stdout).
//!
//! These cover the decision *ordering* in `main` — the ceiling relative to the kind blocklist, the
//! banlist, and the per-pubkey limiter — which unit tests on `Config`/`TokenBucket` cannot reach.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Plugin {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
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

    /// Submit one event, returning the plugin's action ("accept" / "reject" / "shadowReject").
    fn send(&mut self, id: &str, pubkey: &str, kind: u64) -> String {
        writeln!(
            self.stdin,
            r#"{{"type":"new","event":{{"id":"{id}","pubkey":"{pubkey}","kind":{kind}}}}}"#
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("plugin replied");
        assert!(line.contains(&format!("\"id\":\"{id}\"")), "reply was for another event: {line}");
        for action in ["shadowReject", "accept", "reject"] {
            if line.contains(&format!("\"action\":\"{action}\"")) {
                return action.to_string();
            }
        }
        panic!("no action in reply: {line}");
    }

    fn tally(&mut self, n: usize, pubkey: &str, kind: u64) -> (usize, usize, usize) {
        let (mut a, mut s, mut r) = (0, 0, 0);
        for i in 0..n {
            match self.send(&format!("{i:064x}"), pubkey, kind).as_str() {
                "accept" => a += 1,
                "shadowReject" => s += 1,
                _ => r += 1,
            }
        }
        (a, s, r)
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
    let (mut accepted, mut shed) = (0, 0);
    // 200 *distinct* pubkeys, one event each: invisible to a per-pubkey limiter.
    for i in 0..200 {
        match p.send(&format!("{i:064x}"), &format!("{i:064x}"), 22587).as_str() {
            "accept" => accepted += 1,
            "shadowReject" => shed += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert!(shed > 150, "flood was not shed: {shed} shed / {accepted} accepted");
    assert!(accepted <= 12, "let through more than the burst: {accepted}");
}

/// Non-ephemeral traffic must be untouched by the ceiling, even mid-flood.
#[test]
fn ceiling_does_not_touch_normal_kinds() {
    let mut p = Plugin::start(&[
        ("RL_EPHEMERAL_RATE_PER_SEC", "1"),
        ("RL_EPHEMERAL_BURST", "1"),
        ("RL_MAX_EVENTS", "100000"),
    ]);
    p.tally(100, PK_A, 22587); // drain the budget
    let (accepted, shed, rejected) = p.tally(20, PK_B, 1);
    assert_eq!((accepted, shed, rejected), (20, 0, 0), "kind 1 was affected by the ceiling");
}

/// Regression (H2): a banned pubkey must be rejected *before* it can drain the shared budget,
/// otherwise it could deny ephemeral service to everyone else.
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
    let (a, s, r) = p.tally(100, PK_A, 22587);
    assert_eq!((a, s), (0, 0), "banned pubkey consumed budget");
    assert_eq!(r, 100);
    // The budget must be intact for a clean pubkey.
    let (a2, _, _) = p.tally(5, PK_B, 22587);
    assert_eq!(a2, 5, "banned pubkey drained the shared budget");
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
    let (_, _, rejected) = p.tally(60, PK_A, 22587);
    assert!(rejected > 0, "single-source ephemeral flood was never banned");
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
    let (a, s, r) = p.tally(100, PK_A, 20001);
    assert_eq!((a, s, r), (0, 0, 100), "blocked kind was not rejected outright");
    let (a2, _, _) = p.tally(5, PK_B, 22587);
    assert_eq!(a2, 5, "blocked kinds drained the ceiling budget");
}

/// The ceiling is off unless configured, so existing deployments are unaffected.
#[test]
fn ceiling_off_by_default() {
    let mut p = Plugin::start(&[]);
    let (accepted, shed, _) = p.tally(300, PK_A, 22587);
    assert_eq!((accepted, shed), (300, 0), "ceiling was active without configuration");
}
