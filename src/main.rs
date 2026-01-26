//! Distributed Transducer Agent
//!
//! This binary connects to an orchestrator daemon and executes work using Claude Code.
//!
//! # Usage
//!
//! ```bash
//! transducer \
//!   --orchestrator-url=http://localhost:4003 \
//!   --transducer-id=$(hostname) \
//!   --max-concurrent=2
//! ```
//!
//! # Architecture
//!
//! The transducer agent implements a reverse-proxy pattern:
//!
//! 1. Registers with the orchestrator, advertising capabilities
//! 2. Maintains a heartbeat stream to stay registered
//! 3. Receives work assignments via gRPC streaming
//! 4. Spawns `claude --print` subprocesses to execute work
//! 5. Reports progress and results back to orchestrator
//!
//! # Authentication
//!
//! Supports SPIFFE-based mTLS authentication when running in a SPIRE-enabled environment.
//! Falls back to token auth or insecure mode for development.
//!
//! # Naming
//!
//! "Transducer" comes from automata theory - a finite-state machine that transforms
//! input into output. Transducer agents transform work assignments into execution results.

mod spiffe_auth;

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use spiffe_auth::TransducerCredentials;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use transducer_api::{
    ExecutionStatus, HeartbeatRequest, ReceiveWorkRequest, RegisterRequest, SubmitResultRequest,
    TokenUsage, TransducerCapabilities, TransducerMetadata, TransducerServiceClient,
    TransducerStatus,
};
use transducer_sandbox::{Policy, Sandbox};
use uuid::Uuid;

/// Configuration for sandboxed execution
#[derive(Clone)]
struct SandboxConfig {
    policy: Policy,
    socket_path: String,
}

/// Distributed transducer agent for Claude Code workloads
#[derive(Parser, Debug)]
#[command(name = "transducer")]
#[command(about = "Connect Claude Code instances to an orchestrator")]
#[command(version)]
struct Args {
    /// Orchestrator gRPC URL (e.g., http://localhost:4003 or https://daemon.internal:4003)
    #[arg(
        long,
        env = "ORCHESTRATOR_URL",
        default_value = "http://localhost:4003"
    )]
    orchestrator_url: String,

    /// Unique transducer ID (defaults to hostname or SPIFFE ID)
    #[arg(long, env = "TRANSDUCER_ID")]
    transducer_id: Option<String>,

    /// Maximum concurrent work items
    #[arg(long, env = "MAX_CONCURRENT", default_value = "2")]
    max_concurrent: u32,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "15")]
    heartbeat_interval: u64,

    /// Model ID to advertise (e.g., claude-opus-4-5-20251101)
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    model_id: String,

    /// Region for routing (e.g., "sjc", "iad")
    #[arg(long, default_value = "local")]
    region: String,

    /// Working directory for repositories
    #[arg(long, env = "WORK_DIR")]
    work_dir: Option<String>,

    /// Path to claude CLI (defaults to "claude" in PATH)
    #[arg(long, default_value = "claude")]
    claude_path: String,

    /// SPIFFE trust domain for mTLS authentication (e.g., "groundtruth.local")
    #[arg(long, env = "SPIFFE_TRUST_DOMAIN", default_value = "groundtruth.local")]
    spiffe_trust_domain: String,

    /// Disable SPIFFE authentication (use insecure connection)
    #[arg(long, env = "DISABLE_SPIFFE")]
    disable_spiffe: bool,

    /// Path to sandbox policy JSON file (enables sandboxed execution)
    #[arg(long, env = "SANDBOX_POLICY")]
    sandbox_policy: Option<String>,

    /// Socket path for sandbox reflection API
    #[arg(long, env = "SANDBOX_SOCKET", default_value = "/run/transducer/policy.sock")]
    sandbox_socket: String,

    /// Disable sandbox even if policy is configured (for debugging)
    #[arg(long, env = "DISABLE_SANDBOX")]
    disable_sandbox: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required for TLS)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("transducer=info".parse()?)
                .add_directive("tonic=warn".parse()?),
        )
        .init();

    let args = Args::parse();

    // Initialize authentication credentials
    let credentials = if args.disable_spiffe {
        info!("SPIFFE authentication disabled via flag");
        TransducerCredentials::None
    } else {
        TransducerCredentials::auto().await
    };

    // Generate transducer ID, preferring SPIFFE ID if available
    let transducer_id = args
        .transducer_id
        .or_else(|| credentials.identity())
        .unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| Uuid::new_v4().to_string())
        });

    // Load sandbox policy if configured
    let sandbox_config = if args.disable_sandbox {
        info!("Sandbox disabled via flag");
        None
    } else if let Some(ref policy_path) = args.sandbox_policy {
        match Policy::from_file(policy_path) {
            Ok(policy) => {
                info!(
                    policy_path = %policy_path,
                    version = %policy.version,
                    "Loaded sandbox policy"
                );
                Some(SandboxConfig {
                    policy,
                    socket_path: args.sandbox_socket.clone(),
                })
            }
            Err(e) => {
                error!(error = %e, policy_path = %policy_path, "Failed to load sandbox policy");
                return Err(e.into());
            }
        }
    } else {
        info!("No sandbox policy configured - running without isolation");
        None
    };

    info!(
        transducer_id = %transducer_id,
        orchestrator = %args.orchestrator_url,
        max_concurrent = args.max_concurrent,
        spiffe_auth = credentials.is_spiffe(),
        sandboxed = sandbox_config.is_some(),
        "Starting transducer agent"
    );

    // Connect to orchestrator with appropriate authentication
    let channel = credentials
        .connect(&args.orchestrator_url, &args.spiffe_trust_domain)
        .await
        .context("Failed to connect to orchestrator")?;

    let mut client = TransducerServiceClient::new(channel.clone());

    // Register with orchestrator
    let capabilities = TransducerCapabilities {
        supported_work_types: vec![
            "fix_issue".into(),
            "review_pr".into(),
            "refactor_module".into(),
            "add_feature".into(),
            "write_documentation".into(),
            "fix_ci_failure".into(),
            "custom".into(),
        ],
        max_concurrent: args.max_concurrent,
        available_tools: vec![
            "bash".into(),
            "read".into(),
            "edit".into(),
            "write".into(),
            "glob".into(),
            "grep".into(),
            "task".into(),
        ],
        can_access_network: true,
        can_write_files: true,
        model_id: args.model_id.clone(),
        max_context_tokens: 200_000,
    };

    let metadata = TransducerMetadata {
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        region: args.region.clone(),
        labels: HashMap::new(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: std::env::consts::OS.into(),
    };

    let register_response = client
        .register(RegisterRequest {
            transducer_id: transducer_id.clone(),
            capabilities: Some(capabilities.clone()),
            metadata: Some(metadata),
        })
        .await
        .context("Failed to register with orchestrator")?;

    let response = register_response.into_inner();
    if !response.success {
        anyhow::bail!("Registration failed: {}", response.error);
    }

    info!(
        transducer_id = %response.transducer_id,
        ttl_secs = response.ttl_secs,
        "Successfully registered with orchestrator"
    );

    // Track active work count
    let active_work_count = Arc::new(AtomicU32::new(0));

    // Start heartbeat task
    let heartbeat_handle = {
        let transducer_id = transducer_id.clone();
        let active_work_count = active_work_count.clone();
        let heartbeat_interval = args.heartbeat_interval;
        let client = TransducerServiceClient::new(channel.clone());

        tokio::spawn(async move {
            run_heartbeat_loop(client, transducer_id, active_work_count, heartbeat_interval).await
        })
    };

    // Start work receiver
    let work_handle = {
        let transducer_id = transducer_id.clone();
        let active_work_count = active_work_count.clone();
        let max_concurrent = args.max_concurrent;
        let claude_path = args.claude_path.clone();
        let work_dir = args.work_dir.clone();
        let sandbox_config = sandbox_config.clone();
        let client = TransducerServiceClient::new(channel.clone());

        tokio::spawn(async move {
            run_work_loop(
                client,
                transducer_id,
                active_work_count,
                max_concurrent,
                claude_path,
                work_dir,
                sandbox_config,
            )
            .await
        })
    };

    // Wait for tasks to complete (shouldn't happen normally)
    tokio::select! {
        r = heartbeat_handle => {
            warn!("Heartbeat task exited: {:?}", r);
        }
        r = work_handle => {
            warn!("Work task exited: {:?}", r);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    // Deregister
    info!("Deregistering from orchestrator");
    let mut client = TransducerServiceClient::new(channel);
    let _ = client
        .deregister(transducer_api::v1::DeregisterRequest {
            transducer_id,
            reason: "shutdown".into(),
        })
        .await;

    Ok(())
}

/// Run the heartbeat loop to maintain registration
async fn run_heartbeat_loop(
    mut client: TransducerServiceClient<Channel>,
    transducer_id: String,
    active_work_count: Arc<AtomicU32>,
    interval_secs: u64,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<HeartbeatRequest>(32);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    // Spawn sender task
    let sender_id = transducer_id.clone();
    let sender_count = active_work_count.clone();
    tokio::spawn(async move {
        loop {
            interval.tick().await;
            let count = sender_count.load(Ordering::Relaxed);
            let status = if count == 0 {
                TransducerStatus::Idle
            } else {
                TransducerStatus::Busy
            };

            let req = HeartbeatRequest {
                transducer_id: sender_id.clone(),
                status: status as i32,
                active_work_count: count,
                capabilities: None, // Only send on initial registration
            };

            if tx.send(req).await.is_err() {
                break;
            }
        }
    });

    // Start bidirectional stream
    let response = client
        .heartbeat(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .context("Failed to start heartbeat stream")?;

    let mut stream = response.into_inner();

    while let Some(result) = stream.next().await {
        match result {
            Ok(response) => {
                if !response.acknowledged {
                    warn!("Heartbeat not acknowledged, transducer may be deregistered");
                }

                // Handle control signals
                let signal =
                    transducer_api::ControlSignal::try_from(response.control_signal)
                        .unwrap_or(transducer_api::ControlSignal::Continue);

                match signal {
                    transducer_api::ControlSignal::Shutdown => {
                        info!("Received shutdown signal from orchestrator");
                        return Ok(());
                    }
                    transducer_api::ControlSignal::Drain => {
                        info!("Received drain signal - not accepting new work");
                        // TODO: Implement drain mode
                    }
                    _ => {}
                }

                debug!(
                    transducer_id = %transducer_id,
                    next_heartbeat_secs = response.next_heartbeat_secs,
                    "Heartbeat acknowledged"
                );
            }
            Err(e) => {
                error!(error = %e, "Heartbeat stream error");
                return Err(anyhow::anyhow!("Heartbeat stream error: {}", e));
            }
        }
    }

    Ok(())
}

/// Run the work reception loop
async fn run_work_loop(
    mut client: TransducerServiceClient<Channel>,
    transducer_id: String,
    active_work_count: Arc<AtomicU32>,
    max_concurrent: u32,
    claude_path: String,
    work_dir: Option<String>,
    sandbox_config: Option<SandboxConfig>,
) -> Result<()> {
    let response = client
        .receive_work(ReceiveWorkRequest {
            transducer_id: transducer_id.clone(),
            max_concurrent,
        })
        .await
        .context("Failed to start work stream")?;

    let mut stream = response.into_inner();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent as usize));

    while let Some(result) = stream.next().await {
        match result {
            Ok(assignment) => {
                let permit = semaphore.clone().acquire_owned().await?;
                active_work_count.fetch_add(1, Ordering::Relaxed);

                let client_clone = client.clone();
                let transducer_id = transducer_id.clone();
                let active_count = active_work_count.clone();
                let claude_path = claude_path.clone();
                let work_dir = work_dir.clone();
                let sandbox_config = sandbox_config.clone();

                tokio::spawn(async move {
                    let result = execute_work(
                        assignment.assignment_id.clone(),
                        assignment.prompt.clone(),
                        assignment.repo_path.clone(),
                        &claude_path,
                        work_dir.as_deref(),
                        sandbox_config.as_ref(),
                    )
                    .await;

                    // Report result
                    let mut client = client_clone;
                    let (status, summary, error) = match result {
                        Ok((output, _duration_ms)) => {
                            (ExecutionStatus::Completed, output, String::new())
                        }
                        Err(e) => (ExecutionStatus::Failed, String::new(), e.to_string()),
                    };

                    let submit_result = client
                        .submit_result(SubmitResultRequest {
                            transducer_id: transducer_id.clone(),
                            assignment_id: assignment.assignment_id.clone(),
                            status: status as i32,
                            summary,
                            files_modified: vec![],
                            commit_hash: String::new(),
                            pr_number: 0,
                            usage: Some(TokenUsage {
                                input_tokens: 0,
                                output_tokens: 0,
                                cache_read_tokens: 0,
                                cache_creation_tokens: 0,
                                cost_usd: 0.0,
                                model_id: String::new(),
                            }),
                            error,
                            duration_ms: 0,
                            artifacts: vec![],
                        })
                        .await;

                    if let Err(e) = submit_result {
                        error!(error = %e, "Failed to submit work result");
                    }

                    active_count.fetch_sub(1, Ordering::Relaxed);
                    drop(permit);
                });
            }
            Err(e) => {
                error!(error = %e, "Work stream error");
                // Reconnect logic could go here
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}

/// Execute work using Claude Code
async fn execute_work(
    assignment_id: String,
    prompt: String,
    repo_path: String,
    claude_path: &str,
    work_dir: Option<&str>,
    sandbox_config: Option<&SandboxConfig>,
) -> Result<(String, u64)> {
    let start = std::time::Instant::now();

    // Determine working directory
    let cwd = if !repo_path.is_empty() {
        repo_path.clone()
    } else if let Some(dir) = work_dir {
        dir.to_string()
    } else {
        std::env::current_dir()?.to_string_lossy().to_string()
    };

    // Execute with or without sandbox
    let (output, exit_code) = if let Some(config) = sandbox_config {
        info!(
            assignment_id = %assignment_id,
            repo_path = %repo_path,
            sandbox = true,
            "Starting sandboxed work execution"
        );

        execute_sandboxed(&assignment_id, &prompt, &cwd, claude_path, config).await?
    } else {
        info!(
            assignment_id = %assignment_id,
            repo_path = %repo_path,
            sandbox = false,
            "Starting unsandboxed work execution"
        );

        execute_direct(&assignment_id, &prompt, &cwd, claude_path).await?
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        assignment_id = %assignment_id,
        success = exit_code == 0,
        duration_ms = duration_ms,
        "Work execution completed"
    );

    if exit_code == 0 {
        Ok((output, duration_ms))
    } else {
        anyhow::bail!("Claude process exited with code {}: {}", exit_code, output)
    }
}

/// Execute Claude directly (no sandbox)
async fn execute_direct(
    assignment_id: &str,
    prompt: &str,
    cwd: &str,
    claude_path: &str,
) -> Result<(String, i32)> {
    let mut cmd = Command::new(claude_path);
    cmd.arg("--print")
        .arg(prompt)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn claude process")?;

    let (output, errors) = capture_output(&mut child, assignment_id).await?;
    let status = child.wait().await?;

    if !status.success() && !errors.is_empty() {
        return Ok((errors, status.code().unwrap_or(1)));
    }

    Ok((output, status.code().unwrap_or(0)))
}

/// Execute Claude inside sandbox
async fn execute_sandboxed(
    assignment_id: &str,
    prompt: &str,
    cwd: &str,
    claude_path: &str,
    config: &SandboxConfig,
) -> Result<(String, i32)> {
    // Create sandbox with system prompt injection
    let sandbox = Sandbox::with_socket_path(config.policy.clone(), &config.socket_path)
        .context("Failed to create sandbox")?;

    // Generate sandbox-aware system prompt
    let sandbox_prompt = sandbox.generate_system_prompt();

    // Combine sandbox awareness with actual work prompt
    let full_prompt = format!(
        "{}\n\n---\n\n## Your Task\n\n{}",
        sandbox_prompt, prompt
    );

    info!(
        assignment_id = %assignment_id,
        socket_path = %config.socket_path,
        "Executing in sandbox"
    );

    // Run Claude with --dangerously-skip-permissions inside sandbox
    // The sandbox enforces permissions at OS level, so we can skip Claude's prompts
    let command = &[
        claude_path,
        "--dangerously-skip-permissions",
        "--print",
        &full_prompt,
    ];

    // Change to working directory before running sandbox
    std::env::set_current_dir(cwd).context("Failed to change to working directory")?;

    let exit_code = sandbox.run(command).await.context("Sandbox execution failed")?;

    // Note: Output capture is handled differently in sandbox mode
    // The sandbox runs the process directly, so we don't capture stdout/stderr here
    // For now, return empty output - could be improved with a pipe through sandbox
    Ok((String::new(), exit_code))
}

/// Capture stdout/stderr from a child process
async fn capture_output(
    child: &mut tokio::process::Child,
    assignment_id: &str,
) -> Result<(String, String)> {
    let stdout = child.stdout.take().expect("stdout not captured");
    let stderr = child.stderr.take().expect("stderr not captured");

    let stdout_reader = BufReader::new(stdout);
    let stderr_reader = BufReader::new(stderr);

    let mut stdout_lines = stdout_reader.lines();
    let mut stderr_lines = stderr_reader.lines();

    let mut output = String::new();
    let mut errors = String::new();

    loop {
        tokio::select! {
            line = stdout_lines.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        output.push_str(&line);
                        output.push('\n');
                        debug!(assignment_id = %assignment_id, line = %line, "stdout");
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!(error = %e, "Error reading stdout");
                        break;
                    }
                }
            }
            line = stderr_lines.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        errors.push_str(&line);
                        errors.push('\n');
                        debug!(assignment_id = %assignment_id, line = %line, "stderr");
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "Error reading stderr");
                    }
                }
            }
        }
    }

    Ok((output, errors))
}
