# Containerized Transducer Agent
#
# This Dockerfile builds the transducer binary and packages it with
# Claude Code CLI for secure, sandboxed execution.
#
# Security Layers:
# 1. Container isolation (Docker)
# 2. SPIFFE mTLS authentication
# 3. bubblewrap sandboxing for Claude
# 4. Non-root user
# 5. Read-only filesystem
#
# Build:
#   docker build -t transducer-agent .
#
# Run (with SPIRE):
#   docker run --rm \
#     -v /tmp/spire-agent/public:/tmp/spire-agent/public:ro \
#     -v /path/to/workspaces:/workspaces \
#     -l app=transducer \
#     -e ORCHESTRATOR_URL=https://daemon.internal:4003 \
#     transducer-agent

# ============================================================================
# Build Stage - Compile Rust binary
# ============================================================================
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy transducer-api as a local dependency
# In production, this would come from crates.io
COPY ../transducer-api /transducer-api

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer is cached)
RUN cargo build --release || true

# Copy actual source code
COPY src ./src
COPY config ./config

# Build the transducer binary
RUN touch src/main.rs && cargo build --release

# ============================================================================
# Runtime Stage - Minimal image with sandbox tools
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    bubblewrap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI
# Note: This requires the official installation script
# For air-gapped environments, pre-install the CLI in a base image
RUN curl -fsSL https://claude.ai/install.sh | sh || \
    echo "Claude CLI installation skipped (not available during build)"

# Create non-root user for execution
RUN useradd -m -s /bin/bash -u 1000 transducer

# Create directories
RUN mkdir -p /workspaces /tmp/spire-agent/public && \
    chown -R transducer:transducer /workspaces

# Copy built binary
COPY --from=builder /build/target/release/transducer /usr/local/bin/transducer
RUN chmod +x /usr/local/bin/transducer

# Copy config
COPY --from=builder /build/config /etc/transducer

# Labels for SPIRE Docker attestor
# These are matched by workload registration entries
LABEL app=transducer
LABEL version="0.1.0"
LABEL org.opencontainers.image.title="Transducer Agent"
LABEL org.opencontainers.image.description="Distributed Claude Code executor with SPIFFE mTLS"

# Switch to non-root user
USER transducer
WORKDIR /home/transducer

# Environment configuration
ENV SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
ENV WORK_DIR=/workspaces

# Security: Mark filesystem as read-only (except /tmp and /workspaces)
# This is enforced at runtime via docker run --read-only

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep transducer || exit 1

ENTRYPOINT ["transducer"]
CMD ["--help"]
