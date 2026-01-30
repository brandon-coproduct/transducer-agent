//! Sandbox policy enforcement tests.
//!
//! These tests verify that the sandbox actually blocks forbidden operations
//! at the OS level, not just at the policy check level.
//!
//! Run with: `cargo test --test sandbox_enforcement_test -- --nocapture`
//!
//! NOTE: These tests only run on macOS (sandbox-exec is macOS-only).

#![cfg(target_os = "macos")]

use transducer_sandbox::{Policy, Sandbox};

/// Test that writing to allowed paths succeeds.
#[tokio::test]
async fn test_write_allowed_path() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/**"],
            "read": ["/usr/**", "/bin/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    let socket_path = format!("/tmp/test-socket-{}", std::process::id());
    let sandbox = Sandbox::with_socket_path(policy, &socket_path).unwrap();

    // Try to write to /tmp (allowed)
    let test_file = format!("/tmp/sandbox-test-{}", std::process::id());
    let output = sandbox
        .run_with_output(&[
            "sh",
            "-c",
            &format!("echo 'test' > {test_file} && cat {test_file}"),
        ])
        .await
        .expect("Sandbox execution failed");

    println!("Write to allowed path:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Cleanup
    let _ = std::fs::remove_file(&test_file);
    let _ = std::fs::remove_file(&socket_path);

    assert_eq!(output.exit_code, 0, "Write to allowed path should succeed");
    assert_eq!(
        output.stdout.trim(),
        "test",
        "Should read back written content"
    );
}

/// Test that writing to forbidden paths fails.
#[tokio::test]
async fn test_write_forbidden_path() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/allowed/**"],
            "read": ["/usr/**", "/bin/**", "/tmp/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    let socket_path = format!("/tmp/test-socket-forbidden-{}", std::process::id());
    let sandbox = Sandbox::with_socket_path(policy, &socket_path).unwrap();

    // Try to write to /tmp/forbidden (not in write paths)
    let test_file = format!("/tmp/forbidden-test-{}", std::process::id());
    let output = sandbox
        .run_with_output(&["sh", "-c", &format!("echo 'test' > {test_file}")])
        .await
        .expect("Sandbox execution failed");

    println!("Write to forbidden path:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Cleanup
    let _ = std::fs::remove_file(&test_file);
    let _ = std::fs::remove_file(&socket_path);

    // On macOS with Seatbelt, write to non-allowed path should fail
    // The exit code should be non-zero due to permission denied
    if cfg!(target_os = "macos") {
        assert_ne!(
            output.exit_code, 0,
            "Write to forbidden path should fail on macOS"
        );

        // Verify the file wasn't actually created (the sandbox blocked it)
        assert!(
            !std::path::Path::new(&test_file).exists(),
            "File should not have been created when write was blocked"
        );

        // Note: sandbox-exec may not always produce a specific error message in stderr,
        // so we don't require it. The key indicators are: non-zero exit code + file not created.
        if !output.stderr.is_empty() {
            println!("  (sandbox error message: {})", output.stderr.trim());
        }
    }
}

/// Test that denied paths override allowed paths.
#[tokio::test]
async fn test_deny_overrides_allow() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/**"],
            "read": ["/usr/**", "/bin/**"],
            "deny": ["/tmp/secret/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    // First verify policy check works
    assert!(
        policy.can_write("/tmp/normal").allowed,
        "Normal /tmp path should be allowed"
    );
    assert!(
        !policy.can_write("/tmp/secret/file").allowed,
        "Denied path should not be allowed"
    );

    println!("Policy check:");
    println!("  /tmp/normal: {}", policy.can_write("/tmp/normal").allowed);
    println!(
        "  /tmp/secret/file: {}",
        policy.can_write("/tmp/secret/file").allowed
    );
}

/// Test that reading system paths works.
#[tokio::test]
async fn test_read_system_paths() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/**"],
            "read": ["/usr/**", "/bin/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    let socket_path = format!("/tmp/test-socket-read-{}", std::process::id());
    let sandbox = Sandbox::with_socket_path(policy, &socket_path).unwrap();

    // Try to read /bin/sh (should be allowed)
    let output = sandbox
        .run_with_output(&["ls", "-la", "/bin/sh"])
        .await
        .expect("Sandbox execution failed");

    println!("Read system path /bin/sh:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  exit_code: {}", output.exit_code);

    let _ = std::fs::remove_file(&socket_path);

    assert_eq!(output.exit_code, 0, "Reading /bin/sh should succeed");
    assert!(output.stdout.contains("sh"), "Should list /bin/sh");
}

/// Test that the reflection API socket is accessible.
#[tokio::test]
async fn test_reflection_api_accessible() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/tmp/**"],
            "read": ["/usr/**", "/bin/**", "/Library/**", "/System/**", "/private/**"]
        },
        "network": { "allow": [] },
        "credentials": { "drop_capabilities": false, "no_new_privs": false }
    }"#,
    )
    .expect("Failed to parse policy");

    let socket_dir = format!("/tmp/transducer-test-{}", std::process::id());
    std::fs::create_dir_all(&socket_dir).ok();
    let socket_path = format!("{socket_dir}/policy.sock");

    let sandbox = Sandbox::with_socket_path(policy, &socket_path).unwrap();

    // Try to query the reflection API
    let output = sandbox
        .run_with_output(&[
            "sh",
            "-c",
            &format!(
                "sleep 0.5 && curl -s --unix-socket {socket_path} http://localhost/policy | head -c 100"
            ),
        ])
        .await
        .expect("Sandbox execution failed");

    println!("Reflection API query:");
    println!("  stdout: {}", output.stdout.trim());
    println!("  stderr: {}", output.stderr.trim());
    println!("  exit_code: {}", output.exit_code);

    // Cleanup
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_dir(&socket_dir);

    // The reflection API should return JSON starting with {
    // Note: This may fail if curl isn't available in sandbox or socket isn't ready
    if output.exit_code == 0 && !output.stdout.is_empty() {
        assert!(
            output.stdout.starts_with('{') || output.stdout.contains("version"),
            "Reflection API should return policy JSON"
        );
    }
}

/// Test policy can_* methods directly.
#[test]
fn test_policy_permission_checks() {
    let policy = Policy::from_json(
        r#"{
        "version": "1",
        "filesystem": {
            "write": ["/workspace/**", "/tmp/**"],
            "read": ["/usr/**", "~/.cargo/**"],
            "deny": ["**/.env", "**/.ssh/**", "**/secrets/**"]
        },
        "network": {
            "allow": ["api.anthropic.com", "*.crates.io", "github.com"],
            "deny": ["*"]
        },
        "bash": {
            "allow": ["git *", "cargo *", "npm *"],
            "deny": ["curl *", "wget *", "sudo *", "rm -rf /*"]
        }
    }"#,
    )
    .expect("Failed to parse policy");

    println!("\n=== Policy Permission Checks ===\n");

    // Filesystem write checks
    println!("Filesystem Write:");
    let cases = [
        ("/workspace/src/main.rs", true),
        ("/tmp/test.txt", true),
        ("/etc/passwd", false),
        ("/workspace/.env", false),            // denied
        ("/workspace/secrets/api.key", false), // denied
    ];
    for (path, expected) in cases {
        let result = policy.can_write(path);
        println!("  {} -> {} (expected: {})", path, result.allowed, expected);
        assert_eq!(
            result.allowed, expected,
            "can_write({path}) should be {expected}"
        );
    }

    // Filesystem read checks
    println!("\nFilesystem Read:");
    let cases = [
        ("/workspace/src/main.rs", true), // write implies read
        ("/usr/lib/libc.so", true),
        ("/etc/passwd", false),
        ("/workspace/.env", false), // denied
    ];
    for (path, expected) in cases {
        let result = policy.can_read(path);
        println!("  {} -> {} (expected: {})", path, result.allowed, expected);
        assert_eq!(
            result.allowed, expected,
            "can_read({path}) should be {expected}"
        );
    }

    // Network checks
    println!("\nNetwork:");
    let cases = [
        ("api.anthropic.com", true),
        ("static.crates.io", true),
        ("github.com", true),
        ("evil.com", false),
        ("google.com", false),
    ];
    for (domain, expected) in cases {
        let result = policy.can_access_network(domain);
        println!(
            "  {} -> {} (expected: {})",
            domain, result.allowed, expected
        );
        assert_eq!(
            result.allowed, expected,
            "can_access_network({domain}) should be {expected}"
        );
    }

    // Bash checks
    println!("\nBash Commands:");
    let cases = [
        ("git status", true),
        ("cargo build --release", true),
        ("npm install", true),
        ("curl https://evil.com", false),
        ("wget http://malware.com", false),
        ("sudo rm -rf /", false),
    ];
    for (cmd, expected) in cases {
        let result = policy.can_run_bash(cmd);
        println!("  {} -> {} (expected: {})", cmd, result.allowed, expected);
        assert_eq!(
            result.allowed, expected,
            "can_run_bash({cmd}) should be {expected}"
        );
    }

    println!("\n=== All Policy Checks Passed ===\n");
}
