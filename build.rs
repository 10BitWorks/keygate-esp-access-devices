//! Build metadata: stamp the git commit this firmware was built from so the
//! boot banner (and the broker-side log flush) can report it.
//!
//! The hash is baked at compile time (`env!("KEYGATE_GIT_SHA")`) and re-stamped
//! whenever git state changes. A non-git or failed lookup degrades to
//! "unknown" — never fails the build.

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=KEYGATE_GIT_SHA={sha}");
    // Re-stamp when git state changes (commits touch the refs; branch switches
    // touch HEAD). Over-triggering just re-stamps — harmless.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
