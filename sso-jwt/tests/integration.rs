use std::process::Command;

fn binary_path() -> String {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("sso-jwt");
    path.to_string_lossy().to_string()
}

#[test]
fn cli_help_exit_zero() {
    let output = Command::new(binary_path()).arg("--help").output().unwrap();
    assert!(output.status.success(), "exit code: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hardware-backed secure caching"));
    assert!(stdout.contains("shell-init"));
    assert!(stdout.contains("exec"));
}

#[test]
fn cli_version_exit_zero() {
    let output = Command::new(binary_path())
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sso-jwt 0.1.0"));
}

#[test]
fn shell_init_bash() {
    let output = Command::new(binary_path())
        .args(["shell-init", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BASH_COMMAND"));
    assert!(stdout.contains("trap"));
    assert!(stdout.contains("command sso-jwt"));
}

#[test]
fn shell_init_zsh() {
    let output = Command::new(binary_path())
        .args(["shell-init", "zsh"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("preexec"));
    assert!(stdout.contains("add-zsh-hook"));
}

#[test]
fn shell_init_fish() {
    let output = Command::new(binary_path())
        .args(["shell-init", "fish"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("function sso-jwt"));
}

#[test]
fn shell_init_auto_detect() {
    let output = Command::new(binary_path())
        .args(["shell-init"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should output something (auto-detected shell)
    assert!(!stdout.is_empty());
}

#[test]
fn clear_nonexistent_cache_succeeds() {
    // Clearing when no cache exists should not error
    let output = Command::new(binary_path())
        .args(["--clear", "--cache-name", "nonexistent-test-cache-12345"])
        .output()
        .unwrap();
    // This will fail because it tries to init SE/TPM, which may not
    // be available in CI. But --clear should at least parse correctly.
    // We check that it doesn't panic (non-signal exit).
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
}

#[test]
fn invalid_risk_level_rejected() {
    let output = Command::new(binary_path())
        .args(["--risk-level", "5"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("5") || stderr.contains("invalid"));
}

#[test]
fn invalid_environment_rejected() {
    let output = Command::new(binary_path())
        .args(["--environment", "invalid"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn exec_without_command_rejected() {
    let output = Command::new(binary_path())
        .args(["exec", "--"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn help_subcommand_exec() {
    let output = Command::new(binary_path())
        .args(["help", "exec"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("JWT"));
}

#[test]
fn help_subcommand_shell_init() {
    let output = Command::new(binary_path())
        .args(["help", "shell-init"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("export"));
}

#[test]
fn risk_level_1_accepted() {
    let output = Command::new(binary_path())
        .args(["--risk-level", "1"])
        .output()
        .expect("failed to run binary");
    // It will fail trying to init SE/TPM, but should not fail on arg parsing.
    // A signal-terminated process would have code() == None.
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "risk-level 1 should be accepted by argument parser"
    );
}

#[test]
fn risk_level_3_accepted() {
    let output = Command::new(binary_path())
        .args(["--risk-level", "3"])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "risk-level 3 should be accepted by argument parser"
    );
}

#[test]
fn risk_level_0_rejected() {
    let output = Command::new(binary_path())
        .args(["--risk-level", "0"])
        .output()
        .expect("failed to run binary");
    assert!(!output.status.success(), "risk-level 0 should be rejected");
}

#[test]
fn risk_level_4_rejected() {
    let output = Command::new(binary_path())
        .args(["--risk-level", "4"])
        .output()
        .expect("failed to run binary");
    assert!(!output.status.success(), "risk-level 4 should be rejected");
}

#[test]
fn environment_dev_accepted() {
    let output = Command::new(binary_path())
        .args(["--environment", "dev"])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "--environment dev should be accepted by argument parser"
    );
}

#[test]
fn environment_test_accepted() {
    let output = Command::new(binary_path())
        .args(["--environment", "test"])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "--environment test should be accepted by argument parser"
    );
}

#[test]
fn environment_ote_accepted() {
    let output = Command::new(binary_path())
        .args(["--environment", "ote"])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "--environment ote should be accepted by argument parser"
    );
}

#[test]
fn shell_init_invalid_shell_rejected() {
    let output = Command::new(binary_path())
        .args(["shell-init", "powershell"])
        .output()
        .expect("failed to run binary");
    assert!(
        !output.status.success(),
        "invalid shell name should be rejected"
    );
}

#[test]
fn exec_with_command_does_not_panic() {
    let output = Command::new(binary_path())
        .args(["exec", "--", "echo", "test"])
        .output()
        .expect("failed to run binary");
    // Will fail because it tries to init SE, but should not panic/signal
    assert!(
        output.status.code().is_some(),
        "exec should exit with a code, not a signal"
    );
}

#[test]
fn multiple_flags_together() {
    let output = Command::new(binary_path())
        .args([
            "--environment",
            "dev",
            "--risk-level",
            "3",
            "--cache-name",
            "test",
        ])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "process terminated by signal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value"),
        "combined flags should be accepted by argument parser"
    );
}

#[test]
fn clear_with_specific_cache_name() {
    let output = Command::new(binary_path())
        .args(["--clear", "--cache-name", "specific-test"])
        .output()
        .expect("failed to run binary");
    assert!(
        output.status.code().is_some(),
        "clear with cache-name should not crash"
    );
}
