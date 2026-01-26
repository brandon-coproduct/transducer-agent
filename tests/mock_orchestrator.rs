//! Mock orchestrator for end-to-end testing of transducer-agent.
//!
//! Run with: cargo test --test mock_orchestrator -- --nocapture

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use transducer_api::v1::transducer_service_server::{TransducerService, TransducerServiceServer};
use transducer_api::v1::*;

/// Mock orchestrator state
struct MockOrchestrator {
    /// Channel to send work assignments
    work_tx: mpsc::Sender<WorkAssignment>,
    /// Results received from transducers
    results: Arc<Mutex<Vec<SubmitResultRequest>>>,
}

impl MockOrchestrator {
    fn new(work_tx: mpsc::Sender<WorkAssignment>) -> Self {
        Self {
            work_tx,
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[tonic::async_trait]
impl TransducerService for MockOrchestrator {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        println!("📥 Transducer registered: {}", req.transducer_id);
        println!("   Capabilities: {:?}", req.capabilities);

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
                println!(
                    "💓 Heartbeat from {}: status={}, active={}",
                    req.transducer_id, req.status, req.active_work_count
                );

                let response = HeartbeatResponse {
                    acknowledged: true,
                    control_signal: ControlSignal::Continue as i32,
                    next_heartbeat_secs: 15,
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
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
        println!(
            "📬 Transducer {} ready to receive work (max_concurrent={})",
            req.transducer_id, req.max_concurrent
        );

        // Create a channel that we'll use to send work
        let (tx, _rx) = mpsc::channel(10);

        // Forward work from the main work channel
        let _work_tx = self.work_tx.clone();
        let _tx: mpsc::Sender<Result<WorkAssignment, Status>> = tx;
        // Note: In a full implementation, we'd forward from work_tx to tx

        // Return a stream that receives from our channel
        let (response_tx, response_rx) = mpsc::channel(10);

        // Send test work after a delay
        tokio::spawn(async move {
            // Wait for transducer to be ready
            tokio::time::sleep(Duration::from_millis(500)).await;

            let assignment = WorkAssignment {
                assignment_id: "test-assignment-001".into(),
                work_item: Some(WorkItem {
                    id: "work-001".into(),
                    work_type: "custom".into(),
                    priority: WorkPriority::Medium as i32,
                    metadata: vec![],
                }),
                prompt: "What is 2 + 2? Respond with just the number.".into(),
                repo_path: String::new(),
                branch: String::new(),
                deadline: None,
                config: Some(ExecutionConfig {
                    max_turns: 5,
                    turn_timeout_secs: 30,
                    session_timeout_secs: 120,
                    env_vars: std::collections::HashMap::new(),
                    auto_commit: false,
                    create_pr: false,
                }),
            };

            println!("📤 Sending work assignment: {}", assignment.assignment_id);
            let _ = response_tx.send(Ok(assignment)).await;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(response_rx))))
    }

    async fn report_progress(
        &self,
        request: Request<ReportProgressRequest>,
    ) -> Result<Response<ReportProgressResponse>, Status> {
        let req = request.into_inner();
        println!(
            "📊 Progress: {} - {}% - {}",
            req.assignment_id, req.progress_percent, req.status_message
        );

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
        println!("✅ Result received for assignment: {}", req.assignment_id);
        println!("   Status: {:?}", req.status);
        println!("   Summary: {}", req.summary);
        if !req.error.is_empty() {
            println!("   Error: {}", req.error);
        }
        println!("   Duration: {}ms", req.duration_ms);

        self.results.lock().await.push(req);

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
        Ok(Response::new(StatsResponse {
            total_transducers: 0,
            active_transducers: 0,
            work_items_processed: 0,
            work_items_by_status: std::collections::HashMap::new(),
            avg_execution_time_ms: 0,
            utilization_percent: 0.0,
            transducer_stats: vec![],
        }))
    }

    async fn deregister(
        &self,
        request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterResponse>, Status> {
        let req = request.into_inner();
        println!("👋 Transducer deregistered: {} ({})", req.transducer_id, req.reason);

        Ok(Response::new(DeregisterResponse {
            success: true,
            pending_work_items: 0,
        }))
    }
}

#[tokio::test]
async fn test_mock_orchestrator_starts() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let (work_tx, _work_rx) = mpsc::channel(10);
    let orchestrator = MockOrchestrator::new(work_tx);

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let _server = Server::builder().add_service(TransducerServiceServer::new(orchestrator));

    // Just verify it can bind
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    println!("Mock orchestrator would listen on: {}", local_addr);
}

/// Run the mock orchestrator as a standalone server for manual testing.
///
/// Usage:
///   cargo test --test mock_orchestrator run_mock_server -- --nocapture --ignored
///
/// Then in another terminal:
///   cargo run -- --orchestrator-url=http://127.0.0.1:4003 --disable-spiffe
#[tokio::test]
#[ignore]
async fn run_mock_server() {
    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let (work_tx, _work_rx) = mpsc::channel(10);
    let orchestrator = MockOrchestrator::new(work_tx);

    let addr: SocketAddr = "127.0.0.1:4003".parse().unwrap();
    println!("🚀 Starting mock orchestrator on {}", addr);
    println!("");
    println!("To test, run in another terminal:");
    println!("  cd /Users/bcrisp/coproduct/transducer-agent");
    println!("  cargo run -- --orchestrator-url=http://127.0.0.1:4003 --disable-spiffe");
    println!("");

    Server::builder()
        .add_service(TransducerServiceServer::new(orchestrator))
        .serve(addr)
        .await
        .unwrap();
}
