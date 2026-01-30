# Transducer Agent Roadmap

## Current State (v0.1.0)

- [x] gRPC client connecting to orchestrator
- [x] Work assignment and execution flow
- [x] Claude Code CLI integration
- [x] SPIFFE/SPIRE mTLS authentication
- [x] macOS Seatbelt sandbox (basic)
- [x] Linux bubblewrap sandbox (basic)
- [x] Permission lattice (Minimal/Basic/Tools/Permissive)
- [x] Homebrew formula for distribution
- [x] Cross-platform release workflow

---

## Phase 1: Security Hardening (OWASP Agentic AI)

Based on [OWASP Top 10 for Agentic Applications 2026](https://www.practical-devsecops.com/owasp-top-10-agentic-applications/) and [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/).

### 1.1 Prompt Injection Defense

**Risk:** #1 OWASP vulnerability - malicious instructions hidden in external content.

- [ ] Input sanitization for work prompts
- [ ] Unicode homograph detection (invisible characters)
- [ ] Base64/encoded payload detection
- [ ] Tool-call validation (whitelist allowed tools)
- [ ] Output verification before execution

**Test scenarios:** `tests/security/prompt_injection_test.rs`

### 1.2 Excessive Agency Mitigation

**Risk:** Agent takes unintended autonomous actions.

- [ ] Capability budget per work item (max file writes, network calls)
- [ ] Human-in-the-loop for sensitive operations
- [ ] Action logging with cryptographic attestation
- [ ] Rollback checkpoints before destructive operations

### 1.3 Container/Sandbox Escape Prevention

**Risk:** Agent breaks out of sandbox to access host.

- [ ] Audit current Seatbelt/bubblewrap profiles
- [ ] Block `/proc`, `/sys` access
- [ ] Prevent symlink attacks (CVE-2025-31133 style)
- [ ] Network namespace isolation
- [ ] Read-only root filesystem
- [ ] seccomp-bpf syscall filtering

**Test scenarios:** `tests/security/sandbox_escape_test.rs`

### 1.4 Credential/Secret Protection

**Risk:** Agent exfiltrates environment variables or mounted secrets.

- [ ] Strip sensitive env vars before sandbox entry
- [ ] Block access to `~/.aws`, `~/.ssh`, `~/.config`
- [ ] Prevent `/etc/passwd`, `/etc/shadow` reads
- [ ] Audit network egress for data exfiltration patterns

---

## Phase 2: Firecracker MicroVM Integration

Based on [Firecracker security model](https://github.com/firecracker-microvm/firecracker) and [Northflank production patterns](https://northflank.com/blog/secure-runtime-for-codegen-tools-microvms-sandboxing-and-execution-at-scale).

### 2.1 Local Firecracker Support

- [ ] Firecracker VMM installation detection
- [ ] Minimal guest kernel (5MB footprint)
- [ ] Root filesystem with Claude CLI
- [ ] <125ms boot time target
- [ ] Memory ballooning for resource efficiency

### 2.2 Kata Containers / Kubernetes

- [ ] Kata runtime class for transducer pods
- [ ] RuntimeClass selection based on trust level
- [ ] Firecracker backend for Kata
- [ ] devmapper snapshotter for container images

### 2.3 firecracker-containerd Integration

- [ ] containerd shim for Firecracker
- [ ] OCI image support in microVMs
- [ ] Shared volume mounting (virtio-blk)
- [ ] Network namespace bridging

### 2.4 Hybrid Architecture

```
Trust Level    │ Isolation Method
───────────────┼─────────────────────────
Development    │ Process (current sandbox)
Staging        │ gVisor (user-space kernel)
Production     │ Firecracker microVM
Multi-tenant   │ Firecracker + network isolation
```

---

## Phase 3: Advanced Security Features

### 3.1 Behavioral Monitoring

- [ ] Syscall tracing with eBPF
- [ ] Anomaly detection (unexpected file access patterns)
- [ ] Network traffic analysis
- [ ] Token usage anomaly detection

### 3.2 Cryptographic Attestation

- [ ] Work item signing (orchestrator → transducer)
- [ ] Result signing (transducer → orchestrator)
- [ ] Audit log with Merkle tree integrity
- [ ] TPM integration for hardware attestation

### 3.3 Zero Trust Networking

- [ ] Per-work-item network policies
- [ ] DNS allowlist enforcement
- [ ] TLS interception for egress inspection
- [ ] Service mesh integration (Istio/Linkerd)

---

## Security Test Matrix

| Attack Vector | Current | Target | Test File |
|---------------|---------|--------|-----------|
| Direct prompt injection | ❌ | ✅ | `prompt_injection_test.rs` |
| Indirect prompt injection | ❌ | ✅ | `prompt_injection_test.rs` |
| Unicode/encoding attacks | ❌ | ✅ | `prompt_injection_test.rs` |
| Container escape (symlink) | ⚠️ | ✅ | `sandbox_escape_test.rs` |
| Container escape (procfs) | ⚠️ | ✅ | `sandbox_escape_test.rs` |
| Env var exfiltration | ❌ | ✅ | `credential_theft_test.rs` |
| SSH key theft | ⚠️ | ✅ | `credential_theft_test.rs` |
| Network data exfil | ❌ | ✅ | `data_exfil_test.rs` |
| Tool confusion | ❌ | ✅ | `tool_abuse_test.rs` |
| Excessive agency | ❌ | ✅ | `agency_limits_test.rs` |

Legend: ❌ Not addressed | ⚠️ Partial | ✅ Mitigated

---

## References

- [OWASP Top 10 for Agentic Applications 2026](https://www.practical-devsecops.com/owasp-top-10-agentic-applications/)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [Palo Alto: OWASP Agentic AI Security](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)
- [Firecracker GitHub](https://github.com/firecracker-microvm/firecracker)
- [firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd)
- [Northflank: Secure Runtime for Codegen](https://northflank.com/blog/secure-runtime-for-codegen-tools-microvms-sandboxing-and-execution-at-scale)
- [Docker: MCP Prompt Injection Horror Stories](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/)
- [AIShellJack: Prompt Injection in AI Coding Editors](https://arxiv.org/html/2509.22040v1)
- [Browser Sandboxing for AI Agents](https://blaxel.ai/blog/container-escape)
