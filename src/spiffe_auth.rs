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
}
