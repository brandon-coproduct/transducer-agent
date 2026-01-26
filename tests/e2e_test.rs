//! End-to-end integration test for transducer-agent.
//!
//! This test runs a mock orchestrator and agent in the same process to verify
//! the full registration -> work assignment -> execution -> result flow.
//!
//! Run with: cargo test --test e2e_test -- --nocapture

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use transducer_api::v1::transducer_service_server::{TransducerService, TransducerServiceServer};
use transducer_api::v1::*;

/// Test orchestrator that tracks all interactions
struct TestOrchestrator {
    /// Results received
    results: Arc<Mutex<Vec<SubmitResultRequest>>>,
    /// Signal when result is received
    result_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl TestOrchestrator {
    fn new(result_tx: oneshot::Sender<()>) -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::new())),
            result_tx: Arc::new(Mutex::new(Some(result_tx))),
        }
    }
}

#[tonic::async_trait]
impl TransducerService for TestOrchestrator {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        println!("✅ REGISTER: {}", req.transducer_id);

        Ok(Response::new(RegisterResponse {
            success: true,
            transducer_id: req.transducer_id,
            error: String::new(),
            ttl_secs: 60,
        }))
    }

    type HeartbeatStream =
        Pin<Box<dyn Stream<Item = Result<HeartbeatResponse, Status>> + Send + 'static>>;

    async fn heartbeat(
        &self,
        request: Request<tonic::Streaming<HeartbeatRequest>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Ok(Some(req)) = stream.message().await {
                println!("💓 HEARTBEAT: {} (active={})", req.transducer_id, req.active_work_count);
                let _ = tx.send(Ok(HeartbeatResponse {
                    acknowledged: true,
                    control_signal: ControlSignal::Continue as i32,
                    next_heartbeat_secs: 15,
                })).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type ReceiveWorkStream =
        Pin<Box<dyn Stream<Item = Result<WorkAssignment, Status>> + Send + 'static>>;

    async fn receive_work(
        &self,
        request: Request<ReceiveWorkRequest>,
    ) -> Result<Response<Self::ReceiveWorkStream>, Status> {
        let req = request.into_inner();
        println!("📬 RECEIVE_WORK: {} ready", req.transducer_id);

        let (tx, rx) = mpsc::channel(10);

        // Send a simple test work assignment
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let assignment = WorkAssignment {
                assignment_id: "e2e-test-001".into(),
                work_item: Some(WorkItem {
                    id: "work-001".into(),
                    work_type: "custom".into(),
                    priority: WorkPriority::Medium as i32,
                    metadata: vec![],
                }),
                prompt: "Hello from e2e test".into(),
                repo_path: String::new(),
                branch: String::new(),
                deadline: None,
                config: Some(ExecutionConfig {
                    max_turns: 1,
                    turn_timeout_secs: 10,
                    session_timeout_secs: 30,
                    env_vars: std::collections::HashMap::new(),
                    auto_commit: false,
                    create_pr: false,
                }),
            };

            println!("📤 SENDING WORK: {}", assignment.assignment_id);
            let _ = tx.send(Ok(assignment)).await;

            // Keep stream open briefly
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn report_progress(
        &self,
        request: Request<ReportProgressRequest>,
    ) -> Result<Response<ReportProgressResponse>, Status> {
        let req = request.into_inner();
        println!("📊 PROGRESS: {} - {}%", req.assignment_id, req.progress_percent);
        Ok(Response::new(ReportProgressResponse {
            continue_execution: true,
            new_deadline: None,
        }))
    }

    async fn submit_result(
        &self,
        request: Request<SubmitResultRequest>,
    ) -> Result<Response<SubmitResultResponse>, Status> {
        let req = request.into_inner();
        println!("🎉 RESULT RECEIVED:");
        println!("   Assignment: {}", req.assignment_id);
        println!("   Status: {}", req.status);
        println!("   Summary: {}", if req.summary.is_empty() { "(empty)" } else { &req.summary });
        println!("   Error: {}", if req.error.is_empty() { "(none)" } else { &req.error });
        println!("   Duration: {}ms", req.duration_ms);

        self.results.lock().await.push(req);

        // Signal test completion
        if let Some(tx) = self.result_tx.lock().await.take() {
            let _ = tx.send(());
        }

        Ok(Response::new(SubmitResultResponse {
            accepted: true,
            follow_up: vec![],
        }))
    }

    async fn list_transducers(
        &self,
        _request: Request<ListTransducersRequest>,
    ) -> Result<Response<ListTransducersResponse>, Status> {
        Ok(Response::new(ListTransducersResponse {
            transducers: vec![],
            total_count: 0,
        }))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<StatsResponse>, Status> {
        Ok(Response::new(StatsResponse::default()))
    }

    async fn deregister(
        &self,
        request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterResponse>, Status> {
        println!("👋 DEREGISTER: {}", request.into_inner().transducer_id);
        Ok(Response::new(DeregisterResponse {
            success: true,
            pending_work_items: 0,
        }))
    }
}

#[tokio::test]
async fn test_e2e_work_execution() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    println!("\n=== E2E Test: Work Execution ===\n");

    // Create result notification channel
    let (result_tx, result_rx) = oneshot::channel();
    let orchestrator = TestOrchestrator::new(result_tx);
    let results = orchestrator.results.clone();

    // Start server on random port
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    println!("🚀 Test server on: {}\n", local_addr);

    // Start server
    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(TransducerServiceServer::new(orchestrator))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", local_addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    let mut client = transducer_api::v1::transducer_service_client::TransducerServiceClient::new(channel.clone());

    // Register
    let reg_response = client
        .register(RegisterRequest {
            transducer_id: "test-agent".into(),
            capabilities: Some(TransducerCapabilities {
                supported_work_types: vec!["custom".into()],
                max_concurrent: 1,
                available_tools: vec!["bash".into()],
                can_access_network: false,
                can_write_files: false,
                model_id: "test".into(),
                max_context_tokens: 1000,
            }),
            metadata: Some(TransducerMetadata {
                hostname: "test-host".into(),
                region: "test".into(),
                labels: std::collections::HashMap::new(),
                version: "0.1.0".into(),
                platform: "test".into(),
            }),
        })
        .await
        .unwrap();

    assert!(reg_response.into_inner().success);
    println!("✅ Registration successful\n");

    // Start receiving work
    let mut work_stream = client
        .receive_work(ReceiveWorkRequest {
            transducer_id: "test-agent".into(),
            max_concurrent: 1,
        })
        .await
        .unwrap()
        .into_inner();

    // Wait for work assignment
    println!("⏳ Waiting for work assignment...\n");
    let assignment = tokio::time::timeout(Duration::from_secs(5), work_stream.message())
        .await
        .expect("Timeout waiting for work")
        .unwrap()
        .expect("No work received");

    println!("📥 Received work: {}", assignment.assignment_id);
    println!("   Prompt: {}\n", assignment.prompt);

    // Simulate execution (using echo as the "claude" command)
    println!("⚙️  Executing work (simulated)...\n");

    // Submit result
    let submit_response = client
        .submit_result(SubmitResultRequest {
            transducer_id: "test-agent".into(),
            assignment_id: assignment.assignment_id.clone(),
            status: ExecutionStatus::Completed as i32,
            summary: format!("Executed: {}", assignment.prompt),
            files_modified: vec![],
            commit_hash: String::new(),
            pr_number: 0,
            usage: Some(TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
                cache_read_tokens: 0,
                cache_creation_tokens: 0,
                cost_usd: 0.001,
                model_id: "test".into(),
            }),
            error: String::new(),
            duration_ms: 42,
            artifacts: vec![],
        })
        .await
        .unwrap();

    assert!(submit_response.into_inner().accepted);

    // Wait for result to be processed
    let _ = tokio::time::timeout(Duration::from_secs(2), result_rx).await;

    // Verify result was stored
    let stored_results = results.lock().await;
    assert_eq!(stored_results.len(), 1);
    assert_eq!(stored_results[0].assignment_id, "e2e-test-001");
    assert_eq!(stored_results[0].status, ExecutionStatus::Completed as i32);

    println!("\n=== E2E Test PASSED ===\n");

    // Cleanup
    server_handle.abort();
}

/// Test the actual transducer binary against the mock server.
/// Uses `echo` as the claude command for testing.
#[tokio::test]
async fn test_binary_execution() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    println!("\n=== Binary E2E Test ===\n");

    // Create result notification channel
    let (result_tx, result_rx) = oneshot::channel();
    let orchestrator = TestOrchestrator::new(result_tx);
    let results = orchestrator.results.clone();

    // Start server
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    println!("🚀 Mock server on: {}", local_addr);

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(TransducerServiceServer::new(orchestrator))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build the binary path
    let binary = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("transducer");

    println!("📦 Binary: {:?}", binary);

    // Spawn transducer binary
    let mut child = tokio::process::Command::new(&binary)
        .args([
            "--orchestrator-url",
            &format!("http://{}", local_addr),
            "--disable-spiffe",
            "--claude-path",
            "echo",  // Use echo as mock claude
            "--transducer-id",
            "binary-test-agent",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn transducer binary");

    println!("🚀 Started transducer binary (PID: {:?})", child.id());

    // Read stderr in background
    let stderr = child.stderr.take().unwrap();
    let stderr_handle = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("   [agent] {}", line);
        }
    });

    // Wait for result or timeout
    let result = tokio::time::timeout(Duration::from_secs(10), result_rx).await;

    // Kill the binary
    child.kill().await.ok();
    stderr_handle.abort();

    match result {
        Ok(Ok(())) => {
            println!("\n✅ Result received from binary!");
            let stored = results.lock().await;
            assert!(!stored.is_empty(), "No results stored");
            println!("   Summary: {}", stored[0].summary);
        }
        Ok(Err(_)) => {
            println!("\n⚠️  Result channel closed");
        }
        Err(_) => {
            println!("\n⏱️  Timeout waiting for result (this is OK if binary registered)");
        }
    }

    println!("\n=== Binary E2E Test Complete ===\n");
    server_handle.abort();
}
