use std::process::Command;

fn main() {
    // ── Tidiness & Cleanliness Check ───────────────────────────────────────
    println!("cargo:rerun-if-changed=scripts/sh/check_cleanliness.sh");
    let check_status = Command::new("bash")
        .arg("./scripts/sh/check_cleanliness.sh")
        .status()
        .expect("Failed to execute scripts/sh/check_cleanliness.sh");

    if !check_status.success() {
        panic!("Project tidiness check failed! Fix clutter violations before building.");
    }
}
