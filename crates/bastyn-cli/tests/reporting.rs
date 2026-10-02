//! End-to-end tests for the anonymous scan summary, driving the real binary
//! against a local HTTP listener.
//!
//! Every spawn goes through [`bastyn`], which always sets the test endpoint
//! override, so no test can reach a real host: if reporting is enabled the
//! summary goes to the address given, and if the address is a mock that is
//! all that is ever contacted. The override only exists in a build with the
//! `test-endpoint` feature, so the whole file is compiled out without it.

#![cfg(feature = "test-endpoint")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assumption in a test should fail the test"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use assert_cmd::prelude::*;
use bastyn_core::reporting::notice::NOTICE;
use boon::{Compiler, Schemas};
use serde_json::Value;
use tempfile::TempDir;

/// Python that trips `BAS-LLM10-001`: `eval` on a model reply.
const VULNERABLE: &str = r#"
import openai


def advise(question):
    reply = openai.chat.completions.create(messages=[{"role": "user", "content": question}])
    return eval(reply.choices[0].message.content)
"#;

/// Python with nothing to report.
const CLEAN: &str = "def add(a, b):\n    return a + b\n";

/// Variables that change what the scanner believes about where it runs or
/// whether it may report, removed so the host's own settings cannot leak in.
const SCRUBBED: [&str; 8] = [
    "GITHUB_ACTIONS",
    "GITHUB_SERVER_URL",
    "GITHUB_REPOSITORY",
    "GITLAB_CI",
    "CI_SERVER_HOST",
    "CI_PROJECT_PATH",
    "CI",
    "DO_NOT_TRACK",
];

const PREFIX_FAILED: &str = "bastyn: could not send the anonymous scan summary";
const PREFIX_SKIPPED: &str = "bastyn: skipped the anonymous scan summary";

// ---------------------------------------------------------------------------
// Mock collector
// ---------------------------------------------------------------------------

/// One request the mock received.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    /// Header names lowercased, in arrival order.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// A scripted reply: status and extra headers.
type Reply = (u16, Vec<(&'static str, &'static str)>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Read the request and answer from the script (202 when it runs out).
    Answer,
    /// Accept connections and never say anything.
    Silent,
}

/// A loopback HTTP listener that records what it is sent.
struct Mock {
    port: u16,
    records: Arc<Mutex<Vec<Recorded>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Mock {
    /// Answers every request with 202.
    fn accepting() -> Self {
        Self::start(Mode::Answer, Vec::new())
    }

    /// Answers requests from `replies` in order, then 202.
    fn scripted(replies: Vec<Reply>) -> Self {
        Self::start(Mode::Answer, replies)
    }

    /// Accepts connections and never answers.
    fn silent() -> Self {
        Self::start(Mode::Silent, Vec::new())
    }

    fn start(mode: Mode, replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let records = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let records = Arc::clone(&records);
            let connections = Arc::clone(&connections);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut replies = std::collections::VecDeque::from(replies);
                let mut held = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    let Ok((stream, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    stream.set_nonblocking(false).unwrap();
                    if mode == Mode::Silent {
                        held.push(stream);
                        continue;
                    }
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    if let Some(request) = read_request(&stream) {
                        records.lock().unwrap().push(request);
                        let (status, headers) = replies.pop_front().unwrap_or((202, Vec::new()));
                        write_reply(stream, status, &headers);
                    }
                }
            })
        };

        Self {
            port,
            records,
            connections,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/v1/runs", self.port)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.records.lock().unwrap().clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &TcpStream) -> Option<Recorded> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }

    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Recorded {
        method,
        path,
        headers,
        body,
    })
}

fn write_reply(mut stream: TcpStream, status: u16, headers: &[(&str, &str)]) {
    let mut head = format!("HTTP/1.1 {status} Scripted\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.flush();
}

/// A URL on a loopback port nothing is listening on.
fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}/v1/runs")
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

/// The one way a test starts `bastyn`.
///
/// `home` becomes `HOME` and the state directory root, so nothing is read from
/// or written to the real user's directories. `endpoint` is always set: an
/// enabled scan can only ever send to it.
fn bastyn(home: &Path, endpoint: &str) -> Command {
    let mut command = Command::cargo_bin("bastyn").unwrap();
    command.current_dir(home);
    for name in SCRUBBED {
        command.env_remove(name);
    }
    command
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("LOCALAPPDATA", home.join("local"))
        .env("NO_COLOR", "1")
        .env("BASTYN_REPORTING_ENDPOINT_FOR_TESTS", endpoint)
        .env("BASTYN_REPORTING_TIMEOUT_MS_FOR_TESTS", "3000");
    command
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn stderr_lines_starting(output: &Output, prefix: &str) -> usize {
    stderr(output)
        .lines()
        .filter(|line| line.starts_with(prefix))
        .count()
}

fn tree(entries: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, contents) in entries {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
    }
    dir
}

/// A tree whose `.git/config` names `url` as its remote.
fn repo(url: &str, entries: &[(&str, &str)]) -> TempDir {
    let dir = tree(entries);
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(
        dir.path().join(".git/config"),
        format!("[remote \"origin\"]\n\turl = {url}\n"),
    )
    .unwrap();
    dir
}

fn is_empty_dir(path: &Path) -> bool {
    fs::read_dir(path).unwrap().next().is_none()
}

/// Scan `target` against a fresh accepting mock, returning the process output
/// and what the mock received.
fn scan_once(home: &Path, target: &Path) -> (Output, Vec<Recorded>) {
    let mock = Mock::accepting();
    let output = bastyn(home, &mock.url())
        .arg("scan")
        .arg(target)
        .output()
        .unwrap();
    let requests = mock.requests();
    (output, requests)
}

fn sent_body(requests: &[Recorded]) -> Value {
    assert_eq!(requests.len(), 1, "expected exactly one upload");
    requests[0].json()
}

fn project_id_sent(home: &Path, target: &Path) -> (String, String) {
    let (_, requests) = scan_once(home, target);
    let body = sent_body(&requests);
    (
        body["project_id"].as_str().unwrap().to_owned(),
        body["id_source"].as_str().unwrap().to_owned(),
    )
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

fn schema_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bastyn-core/tests/data/reporting/scan-summary.v1.schema.json")
}

fn schema_json() -> Value {
    serde_json::from_str(&fs::read_to_string(schema_path()).unwrap()).unwrap()
}

fn assert_valid(document: &Value) {
    const URL: &str = "https://bastyn.ai/schemas/scan-summary.v1.schema.json";
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler.add_resource(URL, schema_json()).unwrap();
    let index = compiler.compile(URL, &mut schemas).unwrap();
    if let Err(error) = schemas.validate(document, index) {
        panic!("summary does not match the schema: {error:#}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The positive control: if this passes, "nothing was sent" assertions below
/// mean something.
#[test]
fn an_enabled_scan_posts_one_summary() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", VULNERABLE)]);
    let (output, requests) = scan_once(home.path(), project.path());

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/runs");
    assert_eq!(request.header("content-type"), Some("application/json"));
    for name in ["authorization", "cookie", "content-encoding"] {
        assert_eq!(request.header(name), None, "unexpected {name} header");
    }
    assert_valid(&request.json());
}

#[test]
fn every_opt_out_sends_nothing_and_writes_nothing() {
    type Setup = (&'static str, &'static [&'static str], Option<&'static str>);
    let cases: [Setup; 4] = [
        ("--no-reporting", &["--no-reporting"], None),
        ("--offline", &["--offline"], None),
        ("DO_NOT_TRACK=1", &[], Some("1")),
        ("DO_NOT_TRACK=true", &[], Some("true")),
    ];
    for (label, flags, do_not_track) in cases {
        let home = TempDir::new().unwrap();
        let project = tree(&[("agent.py", VULNERABLE)]);
        let mock = Mock::accepting();
        let mut command = bastyn(home.path(), &mock.url());
        command.arg("scan").arg(project.path()).args(flags);
        if let Some(value) = do_not_track {
            command.env("DO_NOT_TRACK", value);
        }
        let output = command.output().unwrap();

        assert_eq!(output.status.code(), Some(1), "{label}");
        assert_eq!(mock.connections(), 0, "{label}");
        assert!(is_empty_dir(home.path()), "{label} wrote to the state dir");
        assert!(
            !stderr(&output).contains(NOTICE),
            "{label} printed a notice"
        );
    }
}

#[test]
fn do_not_track_zero_or_empty_does_not_opt_out() {
    for value in ["0", ""] {
        let home = TempDir::new().unwrap();
        let project = tree(&[("agent.py", VULNERABLE)]);
        let mock = Mock::accepting();
        let output = bastyn(home.path(), &mock.url())
            .env("DO_NOT_TRACK", value)
            .arg("scan")
            .arg(project.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "DO_NOT_TRACK={value:?}");
        assert_eq!(mock.requests().len(), 1, "DO_NOT_TRACK={value:?}");
    }
}

/// Repository-controlled files cannot turn reporting off, redirect it, or run
/// anything.
#[cfg(unix)]
#[test]
fn a_hostile_repository_cannot_change_reporting() {
    let markers = TempDir::new().unwrap();
    let marker = markers.path().join("fsmonitor-ran");
    let project = tree(&[
        ("agent.py", VULNERABLE),
        (
            ".bastynignore",
            "\u{feff}# odd\n!!\n[\n\\\n   \n/../../etc\n**/**/\n",
        ),
    ]);
    fs::create_dir(project.path().join(".git")).unwrap();
    fs::write(
        project.path().join(".git/config"),
        format!(
            "[core]\n\tfsmonitor = touch {marker}\n\tsshCommand = touch {marker}\n\
             [bastyn]\n\treporting = off\n\tendpoint = http://127.0.0.1:1/evil\n\
             [include]\n\tpath = /nonexistent/evil.cfg\n\
             [url \"https://evil.example/\"]\n\tinsteadOf = https://github.com/\n\
             [remote \"origin\"]\n\turl = https://github.com/acme/hostile.git\n",
            marker = marker.display()
        ),
    )
    .unwrap();

    let home = TempDir::new().unwrap();
    let (output, requests) = scan_once(home.path(), project.path());

    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!marker.exists(), "a command named by the repository ran");
    assert_eq!(requests.len(), 1, "reporting must still happen");
    assert_eq!(requests[0].path, "/v1/runs");
    assert_valid(&requests[0].json());
}

#[test]
fn nothing_identifying_leaves_the_machine() {
    const SECRET: &str = "sk-proj-9z8y7x6w5v4u3t2s1r0qponmlkjihgfe";
    let source = format!("API_KEY = \"{SECRET}\"\n{VULNERABLE}");
    let project = repo(
        "git@github.com:AcmeCorp/SuperSecretRepo.git",
        &[("services/ultra_secret_billing/agent.py", &source)],
    );
    let home = TempDir::new().unwrap();

    // The premise: an ordinary run does print the names being hidden, so
    // their absence from the upload is a property of the upload.
    let local = bastyn(home.path(), &closed_port_url())
        .args(["scan", "--no-reporting", "--format", "json"])
        .arg(project.path())
        .output()
        .unwrap();
    assert!(stdout(&local).contains("ultra_secret_billing"));

    let (_, requests) = scan_once(home.path(), project.path());
    let body = sent_body(&requests);
    assert_valid(&body);

    let schema = schema_json();
    let allowed: BTreeSet<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let sent: BTreeSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(sent, allowed, "the top-level keys are exactly the schema's");

    let text = String::from_utf8(requests[0].body.clone())
        .unwrap()
        .to_lowercase();
    let canonical = project.path().canonicalize().unwrap();
    let mut needles = vec![
        SECRET.to_owned(),
        "sk-proj".to_owned(),
        "ultra_secret_billing".to_owned(),
        "services".to_owned(),
        "agent.py".to_owned(),
        "supersecretrepo".to_owned(),
        "acmecorp".to_owned(),
        "github.com".to_owned(),
        project.path().display().to_string(),
        canonical.display().to_string(),
        project
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    ];
    for name in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(user) = std::env::var(name)
            && user.len() >= 4
        {
            needles.push(user);
        }
    }
    for needle in needles {
        assert!(
            !text.contains(&needle.to_lowercase()),
            "the upload contains {needle:?}: {text}"
        );
    }
}

#[test]
fn a_retry_resends_the_identical_body() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", VULNERABLE)]);
    let mock = Mock::scripted(vec![(503, vec![("Retry-After", "0")])]);
    let output = bastyn(home.path(), &mock.url())
        .arg("scan")
        .arg(project.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(
        requests[0].json()["run_id"],
        requests[1].json()["run_id"],
        "a retry is the same run"
    );
    assert_eq!(stderr_lines_starting(&output, PREFIX_FAILED), 0);
}

#[test]
fn a_long_retry_after_gives_up_without_waiting() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", VULNERABLE)]);
    let mock = Mock::scripted(vec![(503, vec![("Retry-After", "300")])]);
    let started = std::time::Instant::now();
    let output = bastyn(home.path(), &mock.url())
        .arg("scan")
        .arg(project.path())
        .output()
        .unwrap();

    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(stderr_lines_starting(&output, PREFIX_FAILED), 1);
}

/// What the collector does in a "never changes the result" case.
enum Server {
    Replies(Vec<Reply>),
    Closed,
    Silent,
}

/// A run with reporting enabled has the same stdout and exit code as one with
/// `--no-reporting`, whatever the collector does, on both a failing and a
/// passing tree and in both machine-readable and text form.
fn assert_result_unchanged(server: &Server, expect_one_failure_line: bool) {
    for (source, exit) in [(VULNERABLE, 1), (CLEAN, 0)] {
        let project = tree(&[("agent.py", source)]);
        for format in ["text", "json"] {
            let baseline_home = TempDir::new().unwrap();
            let baseline = bastyn(baseline_home.path(), &closed_port_url())
                .args(["scan", "--no-reporting", "--format", format])
                .arg(project.path())
                .output()
                .unwrap();
            assert_eq!(baseline.status.code(), Some(exit));

            let home = TempDir::new().unwrap();
            let (mock, url) = match server {
                Server::Replies(replies) => {
                    let mock = Mock::scripted(replies.clone());
                    let url = mock.url();
                    (Some(mock), url)
                }
                Server::Silent => {
                    let mock = Mock::silent();
                    let url = mock.url();
                    (Some(mock), url)
                }
                Server::Closed => (None, closed_port_url()),
            };
            let mut command = bastyn(home.path(), &url);
            if matches!(server, Server::Silent) {
                command.env("BASTYN_REPORTING_TIMEOUT_MS_FOR_TESTS", "200");
            }
            let output = command
                .args(["scan", "--format", format])
                .arg(project.path())
                .output()
                .unwrap();

            assert_eq!(output.status.code(), baseline.status.code(), "{format}");
            assert_eq!(output.stdout, baseline.stdout, "{format}");
            if format == "json" {
                let _: Value = serde_json::from_slice(&output.stdout).unwrap();
            }
            assert_eq!(
                stderr_lines_starting(&output, PREFIX_FAILED),
                usize::from(expect_one_failure_line),
                "{}",
                stderr(&output)
            );
            drop(mock);
        }
    }
}

#[test]
fn an_accepted_upload_changes_nothing() {
    assert_result_unchanged(&Server::Replies(vec![(202, vec![])]), false);
}

#[test]
fn a_rejected_upload_changes_nothing() {
    assert_result_unchanged(&Server::Replies(vec![(422, vec![])]), true);
}

#[test]
fn a_conflicting_upload_changes_nothing() {
    assert_result_unchanged(&Server::Replies(vec![(409, vec![])]), true);
}

#[test]
fn a_failing_collector_changes_nothing() {
    assert_result_unchanged(&Server::Replies(vec![(500, vec![]); 3]), true);
}

#[test]
fn an_unreachable_collector_changes_nothing() {
    assert_result_unchanged(&Server::Closed, true);
}

#[test]
fn a_collector_that_never_answers_changes_nothing() {
    assert_result_unchanged(&Server::Silent, true);
}

#[test]
fn ssh_and_https_spellings_of_a_remote_share_a_project_id() {
    let home = TempDir::new().unwrap();
    let ssh = repo(
        "git@github.com:Acme/Widgets.git",
        &[("agent.py", VULNERABLE)],
    );
    let https = repo(
        "https://github.com/acme/widgets",
        &[("agent.py", VULNERABLE)],
    );
    let other = repo(
        "https://github.com/acme/gadgets",
        &[("agent.py", VULNERABLE)],
    );

    let (ssh_id, ssh_source) = project_id_sent(home.path(), ssh.path());
    let (https_id, https_source) = project_id_sent(home.path(), https.path());
    let (other_id, _) = project_id_sent(home.path(), other.path());

    assert_eq!(ssh_source, "remote");
    assert_eq!(https_source, "remote");
    assert_eq!(ssh_id, https_id);
    assert_ne!(ssh_id, other_id);
}

#[test]
fn a_subdirectory_scan_reports_the_repositorys_id() {
    let home = TempDir::new().unwrap();
    let project = repo(
        "https://github.com/acme/widgets",
        &[("agent.py", VULNERABLE), ("sub/agent.py", VULNERABLE)],
    );
    let (root_id, _) = project_id_sent(home.path(), project.path());
    let (sub_id, source) = project_id_sent(home.path(), &project.path().join("sub"));
    assert_eq!(source, "remote");
    assert_eq!(sub_id, root_id);
}

#[test]
fn without_a_remote_the_id_is_local_and_stable() {
    let home = TempDir::new().unwrap();
    let first = tree(&[("agent.py", VULNERABLE)]);
    let second = tree(&[("agent.py", VULNERABLE)]);

    let (id, source) = project_id_sent(home.path(), first.path());
    assert_eq!(source, "local");
    assert!(
        !is_empty_dir(&home.path().join("state/bastyn")),
        "a local ID must be stored"
    );
    let (again, _) = project_id_sent(home.path(), first.path());
    assert_eq!(again, id);
    let (elsewhere, _) = project_id_sent(home.path(), second.path());
    assert_ne!(elsewhere, id);
}

#[test]
fn without_a_state_directory_a_local_project_sends_nothing() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", VULNERABLE)]);
    let mock = Mock::accepting();
    let output = bastyn(home.path(), &mock.url())
        .env_remove("HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("LOCALAPPDATA")
        .arg("scan")
        .arg(project.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(mock.connections(), 0);
    assert_eq!(stderr_lines_starting(&output, PREFIX_SKIPPED), 1);
}

#[test]
fn the_notice_is_shown_on_the_first_run_only() {
    let home = TempDir::new().unwrap();
    let project = repo(
        "https://github.com/acme/widgets",
        &[("agent.py", VULNERABLE)],
    );

    let (first, _) = scan_once(home.path(), project.path());
    let (second, _) = scan_once(home.path(), project.path());

    assert_eq!(stderr(&first).matches(NOTICE).count(), 1);
    assert_eq!(stderr(&second).matches(NOTICE).count(), 0);
}

#[test]
fn project_id_prints_the_id_scans_report() {
    let home = TempDir::new().unwrap();
    let project = repo(
        "git@github.com:Acme/Widgets.git",
        &[("agent.py", VULNERABLE)],
    );
    let (sent, _) = project_id_sent(home.path(), project.path());

    let mock = Mock::accepting();
    let plain = bastyn(home.path(), &mock.url())
        .arg("project-id")
        .arg(project.path())
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(stdout(&plain), format!("{sent}\n"));

    let explained = bastyn(home.path(), &mock.url())
        .args(["project-id", "--explain"])
        .arg(project.path())
        .output()
        .unwrap();
    assert_eq!(explained.status.code(), Some(0));
    let text = stdout(&explained);
    assert_eq!(text.lines().next(), Some(sent.as_str()));
    for prefix in ["source: remote", "hashed: ", "origin: ", "derivation: "] {
        assert!(
            text.lines().any(|line| line.starts_with(prefix)),
            "missing {prefix:?} in {text}"
        );
    }
    assert_eq!(mock.connections(), 0, "project-id never uses the network");
}

#[test]
fn project_id_reads_a_stored_local_id_and_never_creates_one() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", VULNERABLE)]);
    let mock = Mock::accepting();

    let before = bastyn(home.path(), &mock.url())
        .args(["project-id", "--explain"])
        .arg(project.path())
        .output()
        .unwrap();
    assert_eq!(before.status.code(), Some(0));
    assert!(stdout(&before).starts_with("no project ID yet"));
    assert!(is_empty_dir(home.path()), "project-id created a file");
    assert_eq!(mock.connections(), 0);

    let (sent, source) = project_id_sent(home.path(), project.path());
    assert_eq!(source, "local");
    let after = bastyn(home.path(), &mock.url())
        .args(["project-id", "--explain"])
        .arg(project.path())
        .output()
        .unwrap();
    let text = stdout(&after);
    assert_eq!(text.lines().next(), Some(sent.as_str()));
    assert!(text.contains("source: local"), "{text}");
    assert!(
        text.lines().any(|line| line.starts_with("derivation: ")),
        "{text}"
    );
    assert_eq!(mock.connections(), 0);
}

#[test]
fn the_flag_is_accepted_and_documented() {
    let home = TempDir::new().unwrap();
    let project = tree(&[("agent.py", CLEAN)]);
    let mock = Mock::accepting();

    let output = bastyn(home.path(), &mock.url())
        .args(["scan", "--no-reporting"])
        .arg(project.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(mock.connections(), 0);

    let help = bastyn(home.path(), &mock.url())
        .args(["scan", "--help"])
        .output()
        .unwrap();
    assert!(stdout(&help).contains("--no-reporting"));
}
