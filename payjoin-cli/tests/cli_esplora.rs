//! CLI surface tests for the esplora backend.
//!
//! These tests exercise the binary as a subprocess and assert on exit
//! status / stderr only — no network, no bitcoind, no esplora server.
//! Their job is to catch regressions in argument parsing, feature gating,
//! and the missing-config error paths.

#![cfg(feature = "_esplora")]

use std::process::Command;

fn bin() -> Command { Command::new(env!("CARGO_BIN_EXE_payjoin-cli")) }

#[test]
fn help_succeeds() {
    let output = bin().arg("--help").output().expect("spawn payjoin-cli");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Payjoin"));
    assert!(stdout.contains("--descriptor"));
    assert!(stdout.contains("--esplora-url"));
}

#[test]
fn send_help_succeeds() {
    let output = bin().args(["send", "--help"]).output().expect("spawn payjoin-cli");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fee-rate"));
}

#[test]
fn receive_help_succeeds() {
    let output = bin().args(["receive", "--help"]).output().expect("spawn payjoin-cli");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn missing_subcommand_errors() {
    let output = bin().output().expect("spawn payjoin-cli");
    assert!(!output.status.success());
}

#[test]
fn send_requires_bip21_and_fee_rate() {
    let output = bin().arg("send").output().expect("spawn payjoin-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap reports missing required args
    assert!(stderr.contains("required") || stderr.contains("USAGE") || stderr.contains("Usage"));
}

#[test]
fn invalid_fee_rate_rejected() {
    let output = bin()
        .args(["send", "bitcoin:tb1qexample", "--fee-rate", "not-a-number"])
        .output()
        .expect("spawn payjoin-cli");
    assert!(!output.status.success());
}
