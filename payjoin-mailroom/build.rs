use std::process::Command;

fn main() {
    // Emit the short git commit hash at build time when available.
    if let Some(commit) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        println!("cargo:rustc-env=GIT_COMMIT={commit}");
    }

    // Re-run if HEAD changes (new commit).
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
