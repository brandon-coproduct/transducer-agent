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
//! 4. Spawns `claude -p` subprocesses to execute work
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

mod artifacts;
mod spiffe_auth;

use artifacts::ArtifactCollector;

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
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
    ExecutionStatus, HeartbeatRequest, ReceiveWorkRequest, RegisterRequest, ReportProgressRequest,
    SubmitResultRequest, TokenUsage, TransducerCapabilities, TransducerMetadata,
    TransducerServiceClient, TransducerStatus,
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
    /// Orchestrator gRPC URL (e.g., `http://localhost:4003` or `https://daemon.internal:4003`)
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
    #[arg(
        long,
        env = "SANDBOX_SOCKET",
        default_value = "/run/transducer/policy.sock"
    )]
    sandbox_socket: String,

    /// Disable sandbox even if policy is configured (for debugging)
    #[arg(long, env = "DISABLE_SANDBOX")]
    disable_sandbox: bool,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
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
            hostname::get().map_or_else(
                |_| Uuid::new_v4().to_string(),
                |h| h.to_string_lossy().to_string(),
            )
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
            .map_or_else(|_| "unknown".into(), |h| h.to_string_lossy().to_string()),
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

    // Track active work count and draining state
    let active_work_count = Arc::new(AtomicU32::new(0));
    let is_draining = Arc::new(AtomicBool::new(false));

    // Start heartbeat task
    let heartbeat_handle = {
        let transducer_id = transducer_id.clone();
        let active_work_count = active_work_count.clone();
        let is_draining = is_draining.clone();
        let heartbeat_interval = args.heartbeat_interval;
        let client = TransducerServiceClient::new(channel.clone());

        tokio::spawn(async move {
            run_heartbeat_loop(
                client,
                transducer_id,
                active_work_count,
                is_draining,
                heartbeat_interval,
            )
            .await
        })
    };

    // Start work receiver
    let work_handle = {
        let transducer_id = transducer_id.clone();
        let active_work_count = active_work_count.clone();
        let is_draining = is_draining.clone();
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
                is_draining,
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
    is_draining: Arc<AtomicBool>,
    interval_secs: u64,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<HeartbeatRequest>(32);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    // Spawn sender task
    let sender_id = transducer_id.clone();
    let sender_count = active_work_count.clone();
    let sender_draining = is_draining.clone();
    tokio::spawn(async move {
        loop {
            interval.tick().await;
            let count = sender_count.load(Ordering::Relaxed);
            let draining = sender_draining.load(Ordering::Relaxed);

            let status = if draining {
                TransducerStatus::Draining
            } else if count == 0 {
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
                let signal = transducer_api::ControlSignal::try_from(response.control_signal)
                    .unwrap_or(transducer_api::ControlSignal::Continue);

                match signal {
                    transducer_api::ControlSignal::Shutdown => {
                        info!("Received shutdown signal from orchestrator");
                        return Ok(());
                    }
                    transducer_api::ControlSignal::Drain => {
                        let was_draining = is_draining.swap(true, Ordering::SeqCst);
                        if !was_draining {
                            info!("Entering drain mode - no longer accepting new work");
                        }
                    }
                    transducer_api::ControlSignal::Continue => {
                        // If we were draining and got CONTINUE, exit drain mode
                        let was_draining = is_draining.swap(false, Ordering::SeqCst);
                        if was_draining {
                            info!("Exiting drain mode - resuming work acceptance");
                        }
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
                return Err(anyhow::anyhow!("Heartbeat stream error: {e}"));
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
    is_draining: Arc<AtomicBool>,
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
                // Check drain mode - reject new work if draining
                if is_draining.load(Ordering::Relaxed) {
                    info!(
                        assignment_id = %assignment.assignment_id,
                        "Rejecting work assignment - agent is draining"
                    );
                    // Submit rejected result
                    let _ = client
                        .submit_result(SubmitResultRequest {
                            transducer_id: transducer_id.clone(),
                            assignment_id: assignment.assignment_id.clone(),
                            status: ExecutionStatus::Rejected as i32,
                            summary: String::new(),
                            files_modified: vec![],
                            commit_hash: String::new(),
                            pr_number: 0,
                            usage: None,
                            error: "Agent is draining - cannot accept new work".into(),
                            duration_ms: 0,
                            artifacts: vec![],
                        })
                        .await;
                    continue;
                }

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
                        client_clone.clone(),
                        transducer_id.clone(),
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
                    let (status, summary, error, files_modified, duration_ms, artifacts) =
                        match result {
                            Ok(exec_result) => (
                                ExecutionStatus::Completed,
                                exec_result.output,
                                String::new(),
                                exec_result.files_modified,
                                exec_result.duration_ms,
                                exec_result.artifacts,
                            ),
                            Err(e) => (
                                ExecutionStatus::Failed,
                                String::new(),
                                e.to_string(),
                                vec![],
                                0,
                                vec![],
                            ),
                        };

                    let submit_result = client
                        .submit_result(SubmitResultRequest {
                            transducer_id: transducer_id.clone(),
                            assignment_id: assignment.assignment_id.clone(),
                            status: status as i32,
                            summary,
                            files_modified,
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
                            duration_ms,
                            artifacts,
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

/// Result of work execution including files modified and artifacts
#[derive(Debug)]
struct ExecutionResult {
    output: String,
    duration_ms: u64,
    files_modified: Vec<String>,
    artifacts: Vec<u8>,
}

/// Execute work using Claude Code with progress reporting
async fn execute_work(
    client: TransducerServiceClient<Channel>,
    transducer_id: String,
    assignment_id: String,
    prompt: String,
    repo_path: String,
    claude_path: &str,
    work_dir: Option<&str>,
    sandbox_config: Option<&SandboxConfig>,
) -> Result<ExecutionResult> {
    let start = std::time::Instant::now();

    // Determine working directory
    let cwd = if !repo_path.is_empty() {
        repo_path.clone()
    } else if let Some(dir) = work_dir {
        dir.to_string()
    } else {
        std::env::current_dir()?.to_string_lossy().to_string()
    };

    // Create progress reporter
    let progress_reporter = ProgressReporter::new(
        client,
        transducer_id,
        assignment_id.clone(),
    );

    // Create artifact collector
    let mut artifacts = ArtifactCollector::new();

    // Execute with or without sandbox
    let (output, exit_code, files_modified) = if let Some(config) = sandbox_config {
        info!(
            assignment_id = %assignment_id,
            repo_path = %repo_path,
            sandbox = true,
            "Starting sandboxed work execution"
        );

        let (out, code) = execute_sandboxed(&assignment_id, &prompt, &cwd, claude_path, config).await?;
        let files = progress_reporter.get_files_modified();
        (out, code, files)
    } else {
        info!(
            assignment_id = %assignment_id,
            repo_path = %repo_path,
            sandbox = false,
            "Starting unsandboxed work execution"
        );

        execute_direct_with_progress(&assignment_id, &prompt, &cwd, claude_path, progress_reporter).await?
    };

    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = start.elapsed().as_millis() as u64;

    // Collect execution log artifact
    if !output.is_empty() {
        artifacts.add_log("execution_output", "info", &output);
    }

    // Try to extract git commit info from working directory
    if let Ok(commit_info) = get_last_commit_info(&cwd).await {
        artifacts.add_commit(
            &commit_info.hash,
            &commit_info.message,
            &commit_info.author,
            commit_info.branch.as_deref(),
        );
    }

    info!(
        assignment_id = %assignment_id,
        success = exit_code == 0,
        duration_ms = duration_ms,
        files_modified = files_modified.len(),
        artifacts = artifacts.len(),
        "Work execution completed"
    );

    if exit_code == 0 {
        Ok(ExecutionResult {
            output,
            duration_ms,
            files_modified,
            artifacts: artifacts.to_json_bytes(),
        })
    } else {
        // Still include artifacts even on failure (may have partial results)
        anyhow::bail!("Claude process exited with code {exit_code}: {output}")
    }
}

/// Progress reporter for tracking execution state and reporting to orchestrator
struct ProgressReporter {
    client: TransducerServiceClient<Channel>,
    transducer_id: String,
    assignment_id: String,
    files_modified: Arc<std::sync::Mutex<Vec<String>>>,
    last_report: Arc<std::sync::Mutex<std::time::Instant>>,
}

impl ProgressReporter {
    fn new(
        client: TransducerServiceClient<Channel>,
        transducer_id: String,
        assignment_id: String,
    ) -> Self {
        Self {
            client,
            transducer_id,
            assignment_id,
            files_modified: Arc::new(std::sync::Mutex::new(Vec::new())),
            last_report: Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
        }
    }

    /// Track a file modification
    fn track_file(&self, file: String) {
        if let Ok(mut files) = self.files_modified.lock() {
            if !files.contains(&file) {
                files.push(file);
            }
        }
    }

    /// Get all tracked files
    fn get_files_modified(&self) -> Vec<String> {
        self.files_modified
            .lock()
            .map(|f| f.clone())
            .unwrap_or_default()
    }

    /// Report progress if enough time has passed (throttled to every 10 seconds)
    async fn maybe_report(&self, progress_percent: f32, status_message: &str) {
        let should_report = {
            let mut last = self.last_report.lock().unwrap();
            if last.elapsed() >= Duration::from_secs(10) {
                *last = std::time::Instant::now();
                true
            } else {
                false
            }
        };

        if should_report {
            let files = self.get_files_modified();
            let mut client = self.client.clone();

            let result = client
                .report_progress(ReportProgressRequest {
                    transducer_id: self.transducer_id.clone(),
                    assignment_id: self.assignment_id.clone(),
                    progress_percent,
                    status_message: status_message.to_string(),
                    files_modified: files,
                    usage: None, // Will add when we parse token usage
                })
                .await;

            if let Err(e) = result {
                debug!(error = %e, "Failed to report progress (non-fatal)");
            } else if let Ok(response) = result {
                let resp = response.into_inner();
                if !resp.continue_execution {
                    warn!("Orchestrator requested execution abort");
                    // TODO: Actually abort execution
                }
            }
        }
    }

    /// Parse Claude output line to detect file modifications
    fn parse_line(&self, line: &str) {
        // Common patterns for file modifications in Claude output
        // e.g., "Wrote 42 lines to src/main.rs" or "Edit: src/lib.rs"
        let patterns = [
            ("Wrote ", " to "),
            ("Writing ", " to "),
            ("Edited ", ""),
            ("Edit: ", ""),
            ("Created ", ""),
            ("Modified ", ""),
        ];

        for (prefix, suffix) in patterns {
            if let Some(rest) = line.strip_prefix(prefix) {
                let file = if suffix.is_empty() {
                    rest.trim().to_string()
                } else if let Some(idx) = rest.find(suffix) {
                    rest[idx + suffix.len()..].trim().to_string()
                } else {
                    continue;
                };

                if !file.is_empty() && file.contains('/') || file.contains('.') {
                    self.track_file(file);
                }
            }
        }
    }
}

/// Execute Claude directly with progress reporting
async fn execute_direct_with_progress(
    assignment_id: &str,
    prompt: &str,
    cwd: &str,
    claude_path: &str,
    progress: ProgressReporter,
) -> Result<(String, i32, Vec<String>)> {
    let mut cmd = Command::new(claude_path);
    cmd.arg("--dangerously-skip-permissions")
        .arg("-p")
        .arg(prompt)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn claude process")?;

    let (output, errors) = capture_output_with_progress(&mut child, assignment_id, &progress).await?;
    let status = child.wait().await?;

    // Final progress report
    progress.maybe_report(100.0, "Execution complete").await;

    let files_modified = progress.get_files_modified();

    if !status.success() && !errors.is_empty() {
        return Ok((errors, status.code().unwrap_or(1), files_modified));
    }

    Ok((output, status.code().unwrap_or(0), files_modified))
}

/// Execute Claude directly (no sandbox, no progress reporting)
#[allow(dead_code)]
async fn execute_direct(
    assignment_id: &str,
    prompt: &str,
    cwd: &str,
    claude_path: &str,
) -> Result<(String, i32)> {
    let mut cmd = Command::new(claude_path);
    cmd.arg("--dangerously-skip-permissions")
        .arg("-p")
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
    let full_prompt = format!("{sandbox_prompt}\n\n---\n\n## Your Task\n\n{prompt}");

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
        "-p",
        &full_prompt,
    ];

    // Change to working directory before running sandbox
    std::env::set_current_dir(cwd).context("Failed to change to working directory")?;

    let output = sandbox
        .run_with_output(command)
        .await
        .context("Sandbox execution failed")?;

    // Combine stdout and stderr, preferring stdout if non-empty
    let combined_output = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };

    Ok((combined_output, output.exit_code))
}

/// Capture stdout/stderr from a child process with progress reporting
async fn capture_output_with_progress(
    child: &mut tokio::process::Child,
    assignment_id: &str,
    progress: &ProgressReporter,
) -> Result<(String, String)> {
    let stdout = child.stdout.take().expect("stdout not captured");
    let stderr = child.stderr.take().expect("stderr not captured");

    let stdout_reader = BufReader::new(stdout);
    let stderr_reader = BufReader::new(stderr);

    let mut stdout_lines = stdout_reader.lines();
    let mut stderr_lines = stderr_reader.lines();

    let mut output = String::new();
    let mut errors = String::new();
    let mut line_count: u32 = 0;

    loop {
        tokio::select! {
            line = stdout_lines.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        output.push_str(&line);
                        output.push('\n');
                        debug!(assignment_id = %assignment_id, line = %line, "stdout");

                        // Parse line for file modifications
                        progress.parse_line(&line);

                        // Estimate progress (rough heuristic based on output volume)
                        line_count += 1;
                        let estimated_progress = (line_count as f32 / 100.0).min(95.0);
                        progress.maybe_report(estimated_progress, &line).await;
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

/// Capture stdout/stderr from a child process (no progress reporting)
#[allow(dead_code)]
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

/// Information about a git commit
struct CommitInfo {
    hash: String,
    message: String,
    author: String,
    branch: Option<String>,
}

/// Get information about the last commit in a directory
async fn get_last_commit_info(cwd: &str) -> Result<CommitInfo> {
    // Get commit hash
    let hash_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .await
        .context("Failed to run git rev-parse")?;

    if !hash_output.status.success() {
        anyhow::bail!("git rev-parse failed");
    }

    let hash = String::from_utf8_lossy(&hash_output.stdout)
        .trim()
        .to_string();

    // Get commit message
    let msg_output = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(cwd)
        .output()
        .await
        .context("Failed to run git log")?;

    let message = String::from_utf8_lossy(&msg_output.stdout)
        .trim()
        .to_string();

    // Get author
    let author_output = Command::new("git")
        .args(["log", "-1", "--format=%ae"])
        .current_dir(cwd)
        .output()
        .await
        .context("Failed to run git log for author")?;

    let author = String::from_utf8_lossy(&author_output.stdout)
        .trim()
        .to_string();

    // Get current branch (may fail if detached HEAD)
    let branch_output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .output()
        .await;

    let branch = branch_output.ok().and_then(|o| {
        let b = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if b == "HEAD" || b.is_empty() {
            None
        } else {
            Some(b)
        }
    });

    Ok(CommitInfo {
        hash,
        message,
        author,
        branch,
    })
}
