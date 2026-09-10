use std::{
    fs,
    io::Read,
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use reproit_sdk_platform::process::{CLEANUP_TIMEOUT, ProcessTree, finish_reader};

#[test]
fn process_tree_stops_descendants_after_exit_termination_and_drop() {
    for mode in ["exit", "wait", "drop"] {
        let root = tempfile::tempdir().unwrap();
        let ready = root.path().join("ready");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "descendant_fixture", "--nocapture"])
            .env("REPROIT_PROCESS_FIXTURE", mode)
            .env("REPROIT_PROCESS_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ProcessTree::spawn(command).unwrap();
        let mut stdout = child.take_stdout().unwrap();
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "The descendant did not start.");
            thread::sleep(Duration::from_millis(2));
        }
        let port: u16 = fs::read_to_string(&ready).unwrap().parse().unwrap();
        if mode == "exit" {
            while child.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
        }
        assert!(TcpListener::bind(("127.0.0.1", port)).is_err());
        if mode != "drop" {
            child.terminate().unwrap();
            child.terminate().unwrap();
        }
        drop(child);
        finish_reader(reader, Instant::now() + CLEANUP_TIMEOUT)
            .unwrap()
            .unwrap();
        TcpListener::bind(("127.0.0.1", port)).unwrap();
    }
}

#[test]
#[expect(
    clippy::zombie_processes,
    reason = "The fixture leaves a descendant for the cleanup check."
)]
fn descendant_fixture() {
    let Ok(mode) = std::env::var("REPROIT_PROCESS_FIXTURE") else {
        return;
    };
    let ready = std::env::var_os("REPROIT_PROCESS_READY").unwrap();
    if mode == "descendant" {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        fs::write(ready, listener.local_addr().unwrap().port().to_string()).unwrap();
        thread::sleep(Duration::from_secs(10));
    } else {
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "descendant_fixture", "--nocapture"])
            .env("REPROIT_PROCESS_FIXTURE", "descendant")
            .spawn()
            .unwrap();
        if mode != "exit" {
            descendant.wait().unwrap();
        }
    }
}
