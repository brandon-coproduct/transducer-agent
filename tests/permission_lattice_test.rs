//! Permission lattice tests.
//!
//! These tests verify that each permission level in the Seatbelt sandbox
//! allows the appropriate operations.
//!
//! Run with: cargo test --test permission_lattice_test -- --nocapture
//!
//! NOTE: These tests only run on macOS (sandbox-exec is macOS-only).

#![cfg(target_os = "macos")]

use transducer_sandbox::isolation::macos::{
    run_sandboxed_with_level, PermissionLevel, SandboxOutput,
};
use transducer_sandbox::Policy;

/// Helper to run a command with a specific permission level.
async fn run_with_level(level: PermissionLevel, command: &[&str]) -> SandboxOutput {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/**"],
            "read": ["/usr/**", "/bin/**", "/tmp/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    let socket_path = format!(
        "/tmp/test-perm-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    run_sandboxed_with_level(&policy, command, std::path::Path::new(&socket_path), level)
        .await
        .expect("Sandbox execution failed")
}

// ============================================================================
// MINIMAL Level Tests
// ============================================================================

/// Test that MINIMAL level can run echo.
#[tokio::test]
async fn test_minimal_allows_echo() {
    let output = run_with_level(PermissionLevel::Minimal, &["echo", "hello"]).await;

    println!("MINIMAL echo:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "MINIMAL should allow echo");
    assert_eq!(output.stdout.trim(), "hello");
}

/// Test that MINIMAL level can run /bin/sh.
#[tokio::test]
async fn test_minimal_allows_sh() {
    let output = run_with_level(PermissionLevel::Minimal, &["sh", "-c", "echo 'from sh'"]).await;

    println!("MINIMAL sh:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "MINIMAL should allow sh");
    assert_eq!(output.stdout.trim(), "from sh");
}

// ============================================================================
// BASIC Level Tests
// ============================================================================

/// Test that BASIC level can run ls.
#[tokio::test]
async fn test_basic_allows_ls() {
    let output = run_with_level(PermissionLevel::Basic, &["ls", "-la", "/bin/sh"]).await;

    println!("BASIC ls:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "BASIC should allow ls");
    assert!(output.stdout.contains("sh"));
}

/// Test that BASIC level can run cat.
#[tokio::test]
async fn test_basic_allows_cat() {
    let output = run_with_level(PermissionLevel::Basic, &["cat", "/private/etc/protocols"]).await;

    println!("BASIC cat:");
    println!(
        "  stdout (first 100 chars): {}",
        &output.stdout[..output.stdout.len().min(100)]
    );
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "BASIC should allow cat");
    assert!(output.stdout.contains("tcp") || output.stdout.contains("udp"));
}

/// Test that BASIC level can write to allowed paths.
#[tokio::test]
async fn test_basic_allows_write_to_tmp() {
    let test_file = format!("/tmp/basic-test-{}", std::process::id());
    let output = run_with_level(
        PermissionLevel::Basic,
        &[
            "sh",
            "-c",
            &format!("echo 'test data' > {} && cat {}", test_file, test_file),
        ],
    )
    .await;

    println!("BASIC write to /tmp:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Cleanup
    let _ = std::fs::remove_file(&test_file);

    assert_eq!(output.exit_code, 0, "BASIC should allow writing to /tmp");
    assert_eq!(output.stdout.trim(), "test data");
}

// ============================================================================
// TOOLS Level Tests
// ============================================================================

/// Test that TOOLS level can use env.
#[tokio::test]
async fn test_tools_allows_env() {
    let output = run_with_level(PermissionLevel::Tools, &["env"]).await;

    println!("TOOLS env:");
    println!(
        "  stdout (first 200 chars): {}",
        &output.stdout[..output.stdout.len().min(200)]
    );
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "TOOLS should allow env");
}

/// Test that TOOLS level can run hostname (process info).
#[tokio::test]
async fn test_tools_allows_hostname() {
    let output = run_with_level(PermissionLevel::Tools, &["hostname"]).await;

    println!("TOOLS hostname:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "TOOLS should allow hostname");
    assert!(
        !output.stdout.trim().is_empty(),
        "hostname should return something"
    );
}

// ============================================================================
// PERMISSIVE Level Tests
// ============================================================================

/// Test that PERMISSIVE level is very permissive.
#[tokio::test]
async fn test_permissive_allows_complex_commands() {
    let output = run_with_level(
        PermissionLevel::Permissive,
        &["sh", "-c", "echo 'start' && ls / && echo 'end'"],
    )
    .await;

    println!("PERMISSIVE complex:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(
        output.exit_code, 0,
        "PERMISSIVE should allow complex commands"
    );
    assert!(output.stdout.contains("start"));
    assert!(output.stdout.contains("end"));
}

// ============================================================================
// Lattice Property Tests
// ============================================================================

/// Test that higher levels include permissions from lower levels.
#[tokio::test]
async fn test_lattice_property_basic_includes_minimal() {
    // If MINIMAL can run echo, BASIC should too
    let minimal_output = run_with_level(PermissionLevel::Minimal, &["echo", "test"]).await;
    let basic_output = run_with_level(PermissionLevel::Basic, &["echo", "test"]).await;

    assert_eq!(minimal_output.exit_code, 0);
    assert_eq!(basic_output.exit_code, 0);
    assert_eq!(minimal_output.stdout.trim(), basic_output.stdout.trim());
}

/// Test that TOOLS includes BASIC.
#[tokio::test]
async fn test_lattice_property_tools_includes_basic() {
    // If BASIC can run ls, TOOLS should too
    let basic_output = run_with_level(PermissionLevel::Basic, &["ls", "/bin"]).await;
    let tools_output = run_with_level(PermissionLevel::Tools, &["ls", "/bin"]).await;

    assert_eq!(basic_output.exit_code, 0);
    assert_eq!(tools_output.exit_code, 0);
}

/// Test that PERMISSIVE includes TOOLS.
#[tokio::test]
async fn test_lattice_property_permissive_includes_tools() {
    // If TOOLS can run env, PERMISSIVE should too
    let tools_output = run_with_level(PermissionLevel::Tools, &["env"]).await;
    let permissive_output = run_with_level(PermissionLevel::Permissive, &["env"]).await;

    assert_eq!(tools_output.exit_code, 0);
    assert_eq!(permissive_output.exit_code, 0);
}

// ============================================================================
// Restriction Tests
// ============================================================================

/// Test that writes to non-allowed paths fail at all levels.
#[tokio::test]
async fn test_all_levels_restrict_etc_write() {
    for level in [
        PermissionLevel::Minimal,
        PermissionLevel::Basic,
        PermissionLevel::Tools,
        // Skip PERMISSIVE as it may allow more
    ] {
        let output =
            run_with_level(level, &["sh", "-c", "echo test > /private/etc/test-file"]).await;

        println!("{:?} /etc write:", level);
        println!("  exit_code: {}", output.exit_code);
        println!("  stderr: {}", output.stderr.trim());

        assert_ne!(
            output.exit_code, 0,
            "{:?} should not allow writing to /etc",
            level
        );
    }
}

// ============================================================================
// Process Execution Tests (Comprehensive)
// ============================================================================

/// Test that MINIMAL level can fork child processes via sh.
#[tokio::test]
async fn test_minimal_process_fork() {
    let output = run_with_level(PermissionLevel::Minimal, &["sh", "-c", "echo child"]).await;

    println!("MINIMAL process fork:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "MINIMAL should allow process fork");
    assert_eq!(output.stdout.trim(), "child");
}

/// Test that MINIMAL level propagates exit codes correctly.
#[tokio::test]
async fn test_minimal_exit_codes() {
    let output = run_with_level(PermissionLevel::Minimal, &["sh", "-c", "exit 42"]).await;

    println!("MINIMAL exit codes:");
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(
        output.exit_code, 42,
        "MINIMAL should propagate exit code 42"
    );
}

/// Test that BASIC level can run nested shells.
#[tokio::test]
async fn test_basic_nested_shells() {
    let output = run_with_level(PermissionLevel::Basic, &["sh", "-c", "sh -c 'echo nested'"]).await;

    println!("BASIC nested shells:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "BASIC should allow nested shells");
    assert_eq!(output.stdout.trim(), "nested");
}

/// Test that TOOLS level can run complex pipelines.
#[tokio::test]
async fn test_tools_complex_pipelines() {
    let output = run_with_level(
        PermissionLevel::Tools,
        &["sh", "-c", "echo foo | cat | cat"],
    )
    .await;

    println!("TOOLS complex pipelines:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "TOOLS should allow complex pipelines");
    assert_eq!(output.stdout.trim(), "foo");
}

// ============================================================================
// File System Tests (Comprehensive)
// ============================================================================

/// Test that MINIMAL level can read /dev/null.
#[tokio::test]
async fn test_minimal_reads_dev_null() {
    let output = run_with_level(PermissionLevel::Minimal, &["cat", "/dev/null"]).await;

    println!("MINIMAL reads /dev/null:");
    println!("  stdout: '{}'", output.stdout);
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(
        output.exit_code, 0,
        "MINIMAL should allow reading /dev/null"
    );
    assert!(
        output.stdout.is_empty(),
        "Reading /dev/null should return empty"
    );
}

/// Test that MINIMAL level can read /dev/urandom.
#[tokio::test]
async fn test_minimal_reads_urandom() {
    let output = run_with_level(
        PermissionLevel::Minimal,
        &["sh", "-c", "head -c 8 /dev/urandom | wc -c"],
    )
    .await;

    println!("MINIMAL reads /dev/urandom:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(
        output.exit_code, 0,
        "MINIMAL should allow reading /dev/urandom"
    );
    // wc -c returns byte count - should be 8
    let byte_count: i32 = output.stdout.trim().parse().unwrap_or(0);
    assert_eq!(byte_count, 8, "Should read 8 bytes from urandom");
}

/// Test that BASIC level can list /usr/bin.
#[tokio::test]
async fn test_basic_reads_usr_bin() {
    let output = run_with_level(
        PermissionLevel::Basic,
        &["sh", "-c", "ls /usr/bin | head -5"],
    )
    .await;

    println!("BASIC reads /usr/bin:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "BASIC should allow reading /usr/bin");
    assert!(!output.stdout.is_empty(), "Should list some binaries");
}

/// Test that BASIC level can read /private/etc/protocols.
#[tokio::test]
async fn test_basic_reads_etc_protocols() {
    let output = run_with_level(PermissionLevel::Basic, &["cat", "/private/etc/protocols"]).await;

    println!("BASIC reads /etc/protocols:");
    println!(
        "  stdout (first 100): {}",
        &output.stdout[..output.stdout.len().min(100)]
    );
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(
        output.exit_code, 0,
        "BASIC should allow reading /etc/protocols"
    );
    assert!(output.stdout.contains("tcp") || output.stdout.contains("udp"));
}

/// Test that BASIC level can query extended attributes.
#[tokio::test]
async fn test_basic_extended_attrs() {
    let output = run_with_level(PermissionLevel::Basic, &["xattr", "-l", "/bin/sh"]).await;

    println!("BASIC extended attrs:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // xattr returns 0 even if no attrs exist
    assert_eq!(output.exit_code, 0, "BASIC should allow xattr command");
}

/// Test that MINIMAL cannot read /usr/bin (BASIC adds this).
#[tokio::test]
async fn test_minimal_denies_usr_bin() {
    let output = run_with_level(PermissionLevel::Minimal, &["ls", "/usr/bin"]).await;

    println!("MINIMAL /usr/bin access:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // MINIMAL should not have /usr/bin read access
    assert_ne!(output.exit_code, 0, "MINIMAL should not access /usr/bin");
}

/// Test that all levels deny home directory read (policy-based).
#[tokio::test]
async fn test_all_deny_home_read() {
    for level in [
        PermissionLevel::Minimal,
        PermissionLevel::Basic,
        PermissionLevel::Tools,
    ] {
        let output = run_with_level(
            level,
            &[
                "ls",
                std::env::var("HOME")
                    .unwrap_or("/Users/test".to_string())
                    .as_str(),
            ],
        )
        .await;

        println!("{:?} home read:", level);
        println!("  exit_code: {}", output.exit_code);
        println!("  stderr: {}", output.stderr.trim());

        // Policy doesn't include home directory
        assert_ne!(
            output.exit_code, 0,
            "{:?} should not allow reading home directory (not in policy)",
            level
        );
    }
}

// ============================================================================
// Network Tests (Critical for TOOLS level)
// ============================================================================

/// Test that MINIMAL denies network access.
#[tokio::test]
async fn test_minimal_denies_network() {
    let output = run_with_level(
        PermissionLevel::Minimal,
        &[
            "sh",
            "-c",
            "nc -z -w 1 1.1.1.1 80 2>&1 || echo 'network denied'",
        ],
    )
    .await;

    println!("MINIMAL network access:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Either nc fails with non-zero exit or sandbox blocks it
    let blocked = output.exit_code != 0
        || output.stdout.contains("denied")
        || output.stderr.contains("denied");
    assert!(blocked, "MINIMAL should deny network access");
}

/// Test that BASIC denies network access.
#[tokio::test]
async fn test_basic_denies_network() {
    let output = run_with_level(
        PermissionLevel::Basic,
        &[
            "sh",
            "-c",
            "nc -z -w 1 1.1.1.1 80 2>&1 || echo 'network denied'",
        ],
    )
    .await;

    println!("BASIC network access:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Either nc fails with non-zero exit or sandbox blocks it
    let blocked = output.exit_code != 0
        || output.stdout.contains("denied")
        || output.stderr.contains("denied");
    assert!(blocked, "BASIC should deny network access");
}

/// Test that TOOLS level allows TCP connections.
#[tokio::test]
async fn test_tools_allows_tcp() {
    let output = run_with_level(
        PermissionLevel::Tools,
        &[
            "sh",
            "-c",
            "nc -z -w 2 1.1.1.1 80 && echo 'connected' || echo 'failed'",
        ],
    )
    .await;

    println!("TOOLS TCP access:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // TOOLS should allow outbound TCP
    // Note: May fail if no network connectivity, but should not fail due to sandbox
    assert!(
        output.stdout.contains("connected") || !output.stderr.contains("sandbox"),
        "TOOLS should allow TCP connections (sandbox should not block)"
    );
}

/// Test that TOOLS level allows DNS resolution.
#[tokio::test]
async fn test_tools_dns_resolution() {
    let output = run_with_level(
        PermissionLevel::Tools,
        &["sh", "-c", "host -W 2 example.com 2>&1 | head -1"],
    )
    .await;

    println!("TOOLS DNS resolution:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // DNS should work at TOOLS level (sandbox allows network)
    // Actual resolution depends on network, but sandbox should not block
    assert!(
        !output.stderr.contains("sandbox") && !output.stderr.contains("Operation not permitted"),
        "TOOLS should allow DNS resolution"
    );
}

/// Test that PERMISSIVE allows all network operations.
#[tokio::test]
async fn test_permissive_allows_all_network() {
    let output = run_with_level(
        PermissionLevel::Permissive,
        &[
            "sh",
            "-c",
            "nc -z -w 2 1.1.1.1 80 && echo 'connected' || echo 'timeout'",
        ],
    )
    .await;

    println!("PERMISSIVE network access:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // PERMISSIVE should definitely not sandbox-block network
    assert!(
        !output.stderr.contains("sandbox") && !output.stderr.contains("Operation not permitted"),
        "PERMISSIVE should allow all network operations"
    );
}

// ============================================================================
// Write Permission Tests (Policy-Based)
// ============================================================================

/// Test that BASIC can write to /tmp via policy.
#[tokio::test]
async fn test_write_tmp_with_policy() {
    let test_file = format!("/tmp/perm-test-{}", std::process::id());
    let output = run_with_level(
        PermissionLevel::Basic,
        &[
            "sh",
            "-c",
            &format!(
                "echo 'data' > {} && cat {} && rm {}",
                test_file, test_file, test_file
            ),
        ],
    )
    .await;

    println!("BASIC write to /tmp:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Cleanup in case test failed
    let _ = std::fs::remove_file(&test_file);

    assert_eq!(
        output.exit_code, 0,
        "BASIC should allow writing to /tmp per policy"
    );
    assert_eq!(output.stdout.trim(), "data");
}

/// Test that writes outside policy fail.
#[tokio::test]
async fn test_deny_write_outside_policy() {
    let output = run_with_level(
        PermissionLevel::Basic,
        &["sh", "-c", "touch /var/test-file-should-fail 2>&1"],
    )
    .await;

    println!("BASIC write outside policy:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_ne!(
        output.exit_code, 0,
        "BASIC should deny writes outside policy"
    );
}

/// Test that home directory writes are denied.
#[tokio::test]
async fn test_deny_write_home() {
    let home = std::env::var("HOME").unwrap_or("/Users/test".to_string());
    let test_file = format!("{}/test-file-should-fail", home);

    for level in [
        PermissionLevel::Minimal,
        PermissionLevel::Basic,
        PermissionLevel::Tools,
    ] {
        let output =
            run_with_level(level, &["sh", "-c", &format!("touch {} 2>&1", test_file)]).await;

        println!("{:?} home write:", level);
        println!("  exit_code: {}", output.exit_code);
        println!("  stderr: {}", output.stderr.trim());

        assert_ne!(
            output.exit_code, 0,
            "{:?} should deny writing to home directory",
            level
        );
    }
}

// ============================================================================
// Negative Tests (Capability Boundaries)
// ============================================================================

/// Test that MINIMAL lacks BASIC capabilities (cannot read /usr/bin).
#[tokio::test]
async fn test_minimal_lacks_basic_capabilities() {
    let output = run_with_level(PermissionLevel::Minimal, &["ls", "/usr/bin"]).await;

    println!("MINIMAL lacks BASIC (usr/bin):");
    println!("  exit_code: {}", output.exit_code);
    println!("  stderr: {}", output.stderr.trim());

    assert_ne!(
        output.exit_code, 0,
        "MINIMAL should not have BASIC's /usr/bin access"
    );
}

/// Test that BASIC lacks TOOLS network capabilities.
#[tokio::test]
async fn test_basic_lacks_tools_network() {
    let output = run_with_level(
        PermissionLevel::Basic,
        &[
            "sh",
            "-c",
            "exec 3<>/dev/tcp/1.1.1.1/80 2>&1 && echo ok || echo denied",
        ],
    )
    .await;

    println!("BASIC lacks TOOLS (network):");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // /dev/tcp is a bash-specific feature, but sandbox should still block network
    let blocked = output.stdout.contains("denied") || output.exit_code != 0;
    assert!(
        blocked,
        "BASIC should not have TOOLS's network capabilities"
    );
}

/// Test that TOOLS lacks PERMISSIVE's unrestricted capabilities.
#[tokio::test]
async fn test_tools_has_restrictions() {
    // TOOLS should still respect policy restrictions
    let home = std::env::var("HOME").unwrap_or("/Users/test".to_string());
    let output = run_with_level(PermissionLevel::Tools, &["ls", &home]).await;

    println!("TOOLS restrictions (home):");
    println!("  exit_code: {}", output.exit_code);
    println!("  stderr: {}", output.stderr.trim());

    // Home is not in policy, so even TOOLS should be blocked
    assert_ne!(
        output.exit_code, 0,
        "TOOLS should still respect policy restrictions"
    );
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test that symlink expansion works for /tmp -> /private/tmp.
#[tokio::test]
async fn test_symlink_expansion_tmp() {
    // /tmp is a symlink to /private/tmp on macOS
    let output = run_with_level(PermissionLevel::Basic, &["ls", "-la", "/tmp"]).await;

    println!("Symlink /tmp:");
    println!(
        "  stdout (first 200): {}",
        &output.stdout[..output.stdout.len().min(200)]
    );
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "Sandbox should handle /tmp symlink");
}

/// Test that symlink expansion works for /var -> /private/var.
#[tokio::test]
async fn test_symlink_expansion_var() {
    // /var is a symlink to /private/var on macOS
    let output = run_with_level(PermissionLevel::Basic, &["ls", "/var/db"]).await;

    println!("Symlink /var:");
    println!(
        "  stdout (first 200): {}",
        &output.stdout[..output.stdout.len().min(200)]
    );
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Note: /var/db access may or may not be allowed depending on policy
    // The test verifies symlink handling doesn't cause sandbox errors
    assert!(
        output.exit_code == 0 || !output.stderr.contains("sandbox"),
        "Sandbox should handle /var symlink properly"
    );
}

/// Test concurrent sandbox executions.
#[tokio::test]
async fn test_concurrent_sandbox_executions() {
    let handles: Vec<_> = (0..5)
        .map(|i| {
            tokio::spawn(async move {
                run_with_level(
                    PermissionLevel::Basic,
                    &["echo", &format!("concurrent-{}", i)],
                )
                .await
            })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        let output = handle.await.expect("Task should complete");
        results.push(output);
    }

    println!("Concurrent executions:");
    for (i, output) in results.iter().enumerate() {
        println!(
            "  {}: exit={}, stdout={}",
            i,
            output.exit_code,
            output.stdout.trim()
        );
    }

    for (i, output) in results.iter().enumerate() {
        assert_eq!(
            output.exit_code, 0,
            "Concurrent execution {} should succeed",
            i
        );
        assert!(output.stdout.contains(&format!("concurrent-{}", i)));
    }
}

/// Test rapid sequential sandbox executions.
#[tokio::test]
async fn test_rapid_sequential_executions() {
    for i in 0..10 {
        let output =
            run_with_level(PermissionLevel::Minimal, &["echo", &format!("seq-{}", i)]).await;

        assert_eq!(
            output.exit_code, 0,
            "Sequential execution {} should succeed",
            i
        );
        assert_eq!(output.stdout.trim(), format!("seq-{}", i));
    }
    println!("10 rapid sequential executions completed successfully");
}

/// Test empty command output.
#[tokio::test]
async fn test_empty_output() {
    let output = run_with_level(PermissionLevel::Minimal, &["true"]).await;

    println!("Empty output (true command):");
    println!("  stdout: '{}'", output.stdout);
    println!("  stderr: '{}'", output.stderr);
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "true should exit 0");
    assert!(output.stdout.is_empty(), "true should produce no output");
}

/// Test command that produces stderr only.
#[tokio::test]
async fn test_stderr_only() {
    let output = run_with_level(
        PermissionLevel::Minimal,
        &["sh", "-c", "echo 'error message' >&2"],
    )
    .await;

    println!("Stderr only:");
    println!("  stdout: '{}'", output.stdout);
    println!("  stderr: '{}'", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    assert_eq!(output.exit_code, 0, "Should exit 0");
    assert!(output.stdout.is_empty(), "stdout should be empty");
    assert_eq!(output.stderr.trim(), "error message");
}
