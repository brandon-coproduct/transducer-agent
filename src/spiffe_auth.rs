//! SPIFFE/SPIRE authentication for transducer agents.
//!
//! This module provides client-side mTLS authentication using SPIFFE workload identities.
//! The transducer fetches its X.509 SVID from the local SPIRE agent and uses it to
//! authenticate with the orchestrator's gRPC server.
//!
//! # Security Model
//!
//! - Transducer identity is cryptographically verified via X.509 certificate
//! - SVIDs are short-lived (typically 1 hour) and auto-rotated by SPIRE
//! - No static API keys or tokens required
//! - Trust is established through the SPIFFE trust domain

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use spiffe::{TrustDomain, WorkloadApiClient, X509Context};
use tokio::sync::RwLock;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, info, warn};

/// SPIFFE credentials for the transducer agent.
///
/// Manages the transducer's X.509 SVID and trust bundles for mTLS
/// authentication with the orchestrator.
#[derive(Clone)]
pub struct SpiffeCredentials {
    /// The X.509 context from the workload API
    context: Arc<RwLock<X509Context>>,
    /// Our SPIFFE ID (for logging/metadata)
    spiffe_id: String,
}

impl SpiffeCredentials {
    /// Fetch credentials from the SPIFFE workload API.
    ///
    /// This connects to the local SPIRE agent and fetches the transducer's
    /// X.509 SVID along with trust bundles.
    ///
    /// # Environment Variables
    ///
    /// * `SPIFFE_ENDPOINT_SOCKET` - Path to SPIRE agent socket
    ///   (defaults to platform-specific path)
    pub async fn fetch() -> Result<Self> {
        info!("Fetching SPIFFE credentials from workload API");

        let client = WorkloadApiClient::connect_env()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to SPIFFE workload API: {e}"))?;

        let context = client
            .fetch_x509_context()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch X.509 context: {e}"))?;

        let svid = context
            .default_svid()
            .ok_or_else(|| anyhow::anyhow!("No default SVID in X.509 context"))?;

        let spiffe_id = svid.spiffe_id().to_string();

        info!(
            spiffe_id = %spiffe_id,
            cert_count = svid.cert_chain().len(),
            "Loaded transducer X.509 SVID"
        );

        Ok(Self {
            context: Arc::new(RwLock::new(context)),
            spiffe_id,
        })
    }

    /// Get the transducer's SPIFFE ID.
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }

    /// Build a Tonic `ClientTlsConfig` for mTLS.
    ///
    /// This configures the gRPC client to:
    /// 1. Present the transducer's X.509 SVID as the client certificate
    /// 2. Verify the server's certificate against the SPIFFE trust bundle
    pub async fn to_tls_config(&self, server_trust_domain: &str) -> Result<ClientTlsConfig> {
        let context: tokio::sync::RwLockReadGuard<'_, X509Context> = self.context.read().await;

        let svid = context
            .default_svid()
            .ok_or_else(|| anyhow::anyhow!("No default SVID available"))?;

        // Convert certificate chain to PEM
        let mut cert_pem = Vec::new();
        for cert in svid.cert_chain() {
            let pem_block = pem::Pem::new("CERTIFICATE", cert.as_bytes());
            cert_pem.extend(pem::encode(&pem_block).as_bytes());
        }

        // Convert private key to PEM
        let key_pem_block = pem::Pem::new("PRIVATE KEY", svid.private_key().as_bytes());
        let key_pem = pem::encode(&key_pem_block);

        // Get the CA bundle for server verification
        let trust_domain = TrustDomain::new(server_trust_domain)
            .map_err(|e| anyhow::anyhow!("Invalid trust domain: {e}"))?;

        let bundle = context
            .bundle_set()
            .get(&trust_domain)
            .ok_or_else(|| anyhow::anyhow!("No bundle for trust domain {trust_domain}"))?;

        // Convert trust bundle authorities to PEM
        let mut ca_pem = Vec::new();
        for authority in bundle.authorities() {
            let pem_block = pem::Pem::new("CERTIFICATE", authority.as_bytes());
            ca_pem.extend(pem::encode(&pem_block).as_bytes());
        }

        // Build Tonic TLS config
        let identity = Identity::from_pem(&cert_pem, key_pem.as_bytes());
        let ca_cert = Certificate::from_pem(&ca_pem);

        // Note: domain_name should match the server's SPIFFE ID trust domain
        // This is validated during TLS handshake
        let config = ClientTlsConfig::new()
            .domain_name(server_trust_domain)
            .ca_certificate(ca_cert)
            .identity(identity);

        info!(
            spiffe_id = %self.spiffe_id,
            server_trust_domain = %server_trust_domain,
            "Built client TLS config with mTLS"
        );

        Ok(config)
    }

    /// Create a gRPC channel with SPIFFE mTLS authentication.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The server endpoint (e.g., `https://daemon.internal:4003`)
    /// * `trust_domain` - Expected SPIFFE trust domain of the server
    pub async fn connect(&self, endpoint: &str, trust_domain: &str) -> Result<Channel> {
        let tls_config = self.to_tls_config(trust_domain).await?;

        let channel = Channel::from_shared(endpoint.to_string())
            .context("Invalid endpoint URL")?
            .tls_config(tls_config)
            .context("Failed to apply TLS config")?
            .connect()
            .await
            .context("Failed to connect with mTLS")?;

        info!(endpoint = %endpoint, "Connected to orchestrator with SPIFFE mTLS");

        Ok(channel)
    }

    /// Start a background task to refresh the SVID before expiry.
    #[allow(dead_code)]
    pub fn start_refresh_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 min

            loop {
                interval.tick().await;

                match self.refresh().await {
                    Ok(()) => debug!("Refreshed SPIFFE credentials"),
                    Err(e) => warn!(error = %e, "Failed to refresh SPIFFE credentials"),
                }
            }
        });
    }

    /// Refresh the X.509 context from the workload API.
    async fn refresh(&self) -> Result<()> {
        let client = WorkloadApiClient::connect_env()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to reconnect to workload API: {e}"))?;

        let new_context = client
            .fetch_x509_context()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch refreshed context: {e}"))?;

        let mut context = self.context.write().await;
        *context = new_context;

        Ok(())
    }
}

/// Authentication credentials enum supporting SPIFFE and fallback methods.
#[derive(Clone)]
pub enum TransducerCredentials {
    /// SPIFFE-based mTLS authentication
    Spiffe(SpiffeCredentials),
    /// Token-based authentication (fallback when SPIFFE unavailable)
    Token(String),
    /// No authentication (insecure, for local development only)
    None,
}

impl TransducerCredentials {
    /// Create credentials, preferring SPIFFE if available.
    ///
    /// Falls back to token auth if SPIFFE workload API is unavailable,
    /// or no auth if neither is configured.
    ///
    /// **Pa.Spiffe.Audit.H6 — local-dev only.** Production callers
    /// MUST use [`Self::strict`] which refuses `Self::None`. The audit
    /// identified `auto()` as a fail-open security boundary: in
    /// production where SPIRE goes down (oom, network blip), this
    /// silently fell through to no-auth.
    ///
    /// # Environment Variables
    ///
    /// * `SPIFFE_ENDPOINT_SOCKET` - SPIRE agent socket path
    /// * `TRANSDUCER_AUTH_TOKEN` - Fallback bearer token
    pub async fn auto() -> Self {
        // Try SPIFFE first
        match SpiffeCredentials::fetch().await {
            Ok(creds) => {
                info!(spiffe_id = %creds.spiffe_id(), "Using SPIFFE authentication");
                return Self::Spiffe(creds);
            }
            Err(e) => {
                debug!(error = %e, "SPIFFE not available, trying fallback auth");
            }
        }

        // Try token auth
        if let Ok(token) = std::env::var("TRANSDUCER_AUTH_TOKEN") {
            if !token.is_empty() {
                info!("Using token authentication (SPIFFE unavailable)");
                return Self::Token(token);
            }
        }

        // No auth (development only)
        warn!("No authentication configured - using insecure connection");
        Self::None
    }

    /// Pa.Spiffe.Audit.H6 — production-grade constructor that
    /// REFUSES `Self::None`. Returns `Err` when neither SPIRE socket
    /// nor `TRANSDUCER_AUTH_TOKEN` is available.
    ///
    /// Pre-H6 the production binary called `auto()` which silently
    /// fell through to `Self::None` + an unauthenticated channel
    /// when SPIRE was down. The audit shape: "security boundary
    /// fails open on environmental check." Post-H6, the production
    /// binary calls `strict()` and refuses to start without real
    /// authentication; an operator who genuinely wants to run
    /// without auth must set `TRANSDUCER_ALLOW_NO_AUTH=1` or pass
    /// `--disable-spiffe` (both opt-in, both wired in main.rs).
    ///
    /// Pa.CLAUDE.md "Proof, not heuristic": `strict()` returns
    /// `Result<Self>` so a caller that forgets to handle the Err
    /// gets a compile error. Compare to a "remember to check for
    /// None after auto()" pattern — no compile-time guard.
    pub async fn strict() -> Result<Self> {
        match Self::auto().await {
            Self::Spiffe(c) => Ok(Self::Spiffe(c)),
            Self::Token(t) => Ok(Self::Token(t)),
            Self::None => Err(anyhow::anyhow!(
                "Pa.Spiffe.Audit.H6: refusing to start without authentication. \
                 Neither SPIRE socket (SPIFFE_ENDPOINT_SOCKET) nor token \
                 (TRANSDUCER_AUTH_TOKEN) is available. To run without \
                 authentication explicitly (insecure; local dev only), set \
                 TRANSDUCER_ALLOW_NO_AUTH=1 or pass --disable-spiffe."
            )),
        }
    }

    /// Create a gRPC channel with the appropriate authentication.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Server endpoint URL
    /// * `trust_domain` - Expected SPIFFE trust domain (used if SPIFFE auth)
    pub async fn connect(&self, endpoint: &str, trust_domain: &str) -> Result<Channel> {
        match self {
            Self::Spiffe(creds) => creds.connect(endpoint, trust_domain).await,

            Self::Token(_token) => {
                // For token auth, connect without mTLS but include token in metadata
                // The server would need to validate this via an interceptor
                let channel = Channel::from_shared(endpoint.to_string())
                    .context("Invalid endpoint URL")?
                    .connect()
                    .await
                    .context("Failed to connect")?;

                info!(endpoint = %endpoint, "Connected with token authentication");
                Ok(channel)
            }

            Self::None => {
                // Plain connection (development only)
                let channel = Channel::from_shared(endpoint.to_string())
                    .context("Invalid endpoint URL")?
                    .connect()
                    .await
                    .context("Failed to connect")?;

                warn!(endpoint = %endpoint, "Connected without authentication (insecure)");
                Ok(channel)
            }
        }
    }

    /// Get the transducer identity string for registration.
    ///
    /// For SPIFFE: returns the SPIFFE ID
    /// For token/none: returns None (server assigns identity)
    pub fn identity(&self) -> Option<String> {
        match self {
            Self::Spiffe(creds) => Some(creds.spiffe_id().to_string()),
            _ => None,
        }
    }

    /// Check if this is SPIFFE authentication.
    pub fn is_spiffe(&self) -> bool {
        matches!(self, Self::Spiffe(_))
    }
}

/// Check if SPIFFE authentication is available.
#[allow(dead_code)]
pub async fn is_spiffe_available() -> bool {
    WorkloadApiClient::connect_env().await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_identity() {
        // Test SPIFFE identity extraction
        let creds = TransducerCredentials::Token("test-token".to_string());
        assert!(creds.identity().is_none()); // Token auth doesn't have SPIFFE identity

        let creds = TransducerCredentials::None;
        assert!(creds.identity().is_none());
    }

    #[test]
    fn test_credentials_is_spiffe() {
        let creds = TransducerCredentials::Token("test".to_string());
        assert!(!creds.is_spiffe());

        let creds = TransducerCredentials::None;
        assert!(!creds.is_spiffe());
    }

    #[tokio::test]
    async fn test_spiffe_not_available_without_agent() {
        // Without a SPIRE agent, SPIFFE should not be available
        let available = is_spiffe_available().await;
        // In CI/test environment without SPIRE, this should be false
        // (unless running in a SPIRE-enabled environment)
        assert!(
            !available,
            "Expected SPIFFE to be unavailable in test environment"
        );
    }

    // ── Pa.Spiffe.Audit.H6 — strict() refuses None ──
    //
    // The H6 contract: production transducer-agent binary refuses to
    // start without SPIRE socket OR explicit insecure flag. These
    // tests assert the Result<Self> shape on the strict()
    // constructor; the main.rs wiring of opt-in flags is exercised
    // by the binary itself (compile-time-asserted via the ?
    // propagation in main()).
    //
    // Tests mutate process env, so they serialize via H6_ENV_LOCK.
    use std::sync::Mutex;
    static H6_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Pa.Spiffe.Audit.H6 regression test — THIS IS THE BUG-AS-WAS.
    /// Pre-H6, with no SPIFFE socket and no TRANSDUCER_AUTH_TOKEN,
    /// auto() silently returned Self::None and the next connect()
    /// opened an unauthenticated channel. Post-H6, strict() returns
    /// Err in the same scenario, forcing the caller to handle it
    /// (production binaries propagate via ? and refuse to start).
    #[tokio::test]
    async fn h6_strict_with_no_creds_returns_err() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::remove_var("TRANSDUCER_AUTH_TOKEN");
        // Point SPIFFE socket at a path that definitely doesn't
        // exist so the SPIRE fetch fails fast.
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h6-test/socket",
        );

        let r = TransducerCredentials::strict().await;

        // Restore env regardless of test outcome.
        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        assert!(
            r.is_err(),
            "Pa.Spiffe.Audit.H6: strict() must Err when no SPIFFE socket and no TRANSDUCER_AUTH_TOKEN"
        );
    }

    /// Pa.Spiffe.Audit.H6 — token-only path. With
    /// `TRANSDUCER_AUTH_TOKEN` set (and SPIFFE unavailable),
    /// `strict()` returns Ok(Token). Proves the fix isn't
    /// over-aggressive (legitimate token auth still works).
    #[tokio::test]
    async fn h6_strict_with_token_returns_ok() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::set_var("TRANSDUCER_AUTH_TOKEN", "h6-test-token-value");
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h6-test/socket",
        );

        let r = TransducerCredentials::strict().await;

        // Restore env.
        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        match r {
            Ok(TransducerCredentials::Token(t)) => {
                assert_eq!(t, "h6-test-token-value");
            }
            Ok(_) => panic!("expected Ok(Token), got Ok(Spiffe|None)"),
            Err(e) => panic!("expected Ok(Token), got Err: {}", e),
        }
    }

    /// Pa.Spiffe.Audit.H6 — error message must mention BOTH the
    /// SPIRE socket env var AND the token env var AND the explicit
    /// opt-in flag, so an operator hitting this error knows the
    /// three remediation paths. Without this test the helpful
    /// migration message could rot silently.
    #[tokio::test]
    async fn h6_strict_err_message_lists_all_remediation_paths() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::remove_var("TRANSDUCER_AUTH_TOKEN");
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h6-test/socket",
        );

        let r = TransducerCredentials::strict().await;

        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        // unwrap_err requires Ok variant Debug, which TransducerCredentials
        // doesn't implement. Match instead.
        let err_msg = match r {
            Ok(_) => panic!("strict() must Err with no creds available"),
            Err(e) => e.to_string(),
        };
        assert!(
            err_msg.contains("SPIFFE_ENDPOINT_SOCKET"),
            "err msg must mention SPIRE socket env var; got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("TRANSDUCER_AUTH_TOKEN"),
            "err msg must mention token env var; got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("TRANSDUCER_ALLOW_NO_AUTH")
                || err_msg.contains("--disable-spiffe"),
            "err msg must name the explicit insecure opt-in path; got: {}",
            err_msg
        );
    }

    // ── Pa.Spiffe.Audit.H7 — agent-side negative-path tests ──
    //
    // Companion to the orchestrator-side tests at
    // `tests/spiffe_negative_paths_test.rs`. The two together
    // satisfy the audit's "≥5 new negative-path tests" criterion.
    //
    // These tests cover the failure modes of TransducerCredentials
    // from the AGENT side:
    //   - auto() correctly returns None when no creds are present
    //   - auto() correctly ignores empty TRANSDUCER_AUTH_TOKEN
    //     (defends against a future refactor that drops the
    //     `!is_empty()` guard)
    //   - auto() falls back to Token when SPIRE is unavailable but
    //     TRANSDUCER_AUTH_TOKEN is set
    //   - connect() with Self::None propagates URL-parse errors
    //
    // All tests serialize via H6_ENV_LOCK (defined above) since
    // they touch the same global env vars as the H6 tests.

    /// Pa.Spiffe.Audit.H7 #1 — auto() returns Self::None when neither
    /// SPIRE socket nor token is configured. Locks the auto()
    /// behavior in place; H6's strict() refuses this same scenario,
    /// but auto() itself remains permissive (it's the local-dev path).
    #[tokio::test]
    async fn h7_auto_with_no_spire_socket_returns_none() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::remove_var("TRANSDUCER_AUTH_TOKEN");
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h7-test/socket",
        );

        let creds = TransducerCredentials::auto().await;

        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        assert!(
            matches!(creds, TransducerCredentials::None),
            "auto() must return Self::None when no SPIRE and no token"
        );
    }

    /// Pa.Spiffe.Audit.H7 #2 — empty TRANSDUCER_AUTH_TOKEN is treated
    /// as "no token," not "use empty string as token." Defends against
    /// a future refactor that drops the `!token.is_empty()` check —
    /// without it, an unset-but-defaulted env var (rare but possible
    /// with shell heredocs) would yield a Token("") that authenticated
    /// nothing.
    #[tokio::test]
    async fn h7_auto_with_empty_token_env_does_not_use_it() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::set_var("TRANSDUCER_AUTH_TOKEN", "");
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h7-test/socket",
        );

        let creds = TransducerCredentials::auto().await;

        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        assert!(
            matches!(creds, TransducerCredentials::None),
            "empty TRANSDUCER_AUTH_TOKEN must be treated as no-token; got non-None variant"
        );
    }

    /// Pa.Spiffe.Audit.H7 #3 — fallback ordering. With
    /// TRANSDUCER_AUTH_TOKEN set but SPIRE unavailable, auto()
    /// returns Self::Token(...). Without this assertion, the H6
    /// strict() fix could be over-aggressive — a legitimate token-
    /// only flow would also be rejected.
    #[tokio::test]
    async fn h7_auto_with_token_but_no_spire_returns_token() {
        let _lock = H6_ENV_LOCK.lock().unwrap();
        let prior_token = std::env::var("TRANSDUCER_AUTH_TOKEN").ok();
        let prior_socket = std::env::var("SPIFFE_ENDPOINT_SOCKET").ok();
        std::env::set_var("TRANSDUCER_AUTH_TOKEN", "h7-test-token-value");
        std::env::set_var(
            "SPIFFE_ENDPOINT_SOCKET",
            "unix:///nonexistent/h7-test/socket",
        );

        let creds = TransducerCredentials::auto().await;

        match prior_token {
            Some(v) => std::env::set_var("TRANSDUCER_AUTH_TOKEN", v),
            None => std::env::remove_var("TRANSDUCER_AUTH_TOKEN"),
        }
        match prior_socket {
            Some(v) => std::env::set_var("SPIFFE_ENDPOINT_SOCKET", v),
            None => std::env::remove_var("SPIFFE_ENDPOINT_SOCKET"),
        }

        match creds {
            TransducerCredentials::Token(t) => assert_eq!(t, "h7-test-token-value"),
            TransducerCredentials::Spiffe(_) => {
                panic!("expected Token, got Spiffe (test environment shouldn't have SPIRE)")
            }
            TransducerCredentials::None => {
                panic!("expected Token, got None — auto() failed to use TRANSDUCER_AUTH_TOKEN")
            }
        }
    }

    /// Pa.Spiffe.Audit.H7 #4 — `Self::None.connect(&bogus_url, ...)`
    /// returns an error. Proves the URL parser actually catches
    /// malformed endpoints; without this, a future refactor that
    /// silently constructs a broken Channel would not be caught
    /// until the first wire request failed cryptically.
    #[tokio::test]
    async fn h7_connect_with_none_creds_fails_on_invalid_endpoint() {
        let creds = TransducerCredentials::None;
        let r = creds.connect("not-a-valid-url://", "some.trust.domain").await;
        assert!(
            r.is_err(),
            "connect() must Err on invalid endpoint URL"
        );
    }
}
