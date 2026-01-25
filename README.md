# transducer-agent

A distributed executor agent that connects to an orchestrator and executes work using [Claude Code](https://claude.ai/code).

## What is Transducer?

**Transducer** is named after [automata theory](https://en.wikipedia.org/wiki/Finite-state_transducer): a finite-state machine that transforms input into output. Transducer agents transform work assignments into execution results by running Claude Code.

## Architecture

```
                    ┌──────────────────────────────────┐
                    │         Orchestrator             │
                    │         (gRPC Server)            │
                    └──────────────────────────────────┘
                               ▲       │
                        gRPC   │       │  Work
                    Heartbeat  │       │  Assignments
                               │       ▼
    ┌──────────────────────────────────────────────────────────┐
    │                    Transducer Agents                     │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
    │  │ transducer-1 │  │ transducer-2 │  │ transducer-N │   │
    │  │  (Claude)    │  │  (Claude)    │  │  (Claude)    │   │
    │  └──────────────┘  └──────────────┘  └──────────────┘   │
    └──────────────────────────────────────────────────────────┘
```

## Installation

### From Source

```bash
git clone https://github.com/coproduct/transducer-agent
cd transducer-agent
cargo install --path .
```

### From crates.io

```bash
cargo install transducer-agent
```

### Docker

```bash
docker pull ghcr.io/coproduct/transducer-agent:latest
```

## Usage

### Basic Usage

```bash
# Connect to a local orchestrator
transducer --orchestrator-url http://localhost:4003

# With custom ID and concurrency
transducer \
  --orchestrator-url http://orchestrator.internal:4003 \
  --transducer-id worker-1 \
  --max-concurrent 4
```

### Command-Line Options

```
transducer [OPTIONS]

Options:
  --orchestrator-url <URL>    Orchestrator gRPC URL [env: ORCHESTRATOR_URL] [default: http://localhost:4003]
  --transducer-id <ID>        Unique transducer ID [env: TRANSDUCER_ID]
  --max-concurrent <N>        Maximum concurrent work items [env: MAX_CONCURRENT] [default: 2]
  --heartbeat-interval <SEC>  Heartbeat interval in seconds [default: 15]
  --model-id <MODEL>          Model ID to advertise [default: claude-sonnet-4-20250514]
  --region <REGION>           Region for routing [default: local]
  --work-dir <PATH>           Working directory [env: WORK_DIR]
  --claude-path <PATH>        Path to claude CLI [default: claude]
  --spiffe-trust-domain <TD>  SPIFFE trust domain [env: SPIFFE_TRUST_DOMAIN] [default: groundtruth.local]
  --disable-spiffe            Disable SPIFFE authentication [env: DISABLE_SPIFFE]
  -h, --help                  Print help
  -V, --version               Print version
```

### Docker Usage

```bash
# Without SPIFFE (development)
docker run --rm \
  -v /path/to/workspaces:/workspaces \
  -e ORCHESTRATOR_URL=http://host.docker.internal:4003 \
  -e DISABLE_SPIFFE=true \
  ghcr.io/coproduct/transducer-agent

# With SPIFFE (production)
docker run --rm \
  -v /tmp/spire-agent/public:/tmp/spire-agent/public:ro \
  -v /workspaces:/workspaces \
  -e ORCHESTRATOR_URL=https://orchestrator.internal:4003 \
  ghcr.io/coproduct/transducer-agent
```

## Authentication

### SPIFFE/SPIRE (Recommended)

Transducer supports zero-trust workload identity via [SPIFFE](https://spiffe.io/):

1. Transducer fetches X.509 SVID from local SPIRE agent
2. Establishes mTLS connection to orchestrator
3. SVIDs are automatically rotated (typically every hour)

```bash
# Set the SPIRE agent socket (usually auto-detected)
export SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
export SPIFFE_TRUST_DOMAIN=mycompany.io

transducer --orchestrator-url https://orchestrator.internal:4003
```

### Token Authentication

Fallback when SPIFFE is unavailable:

```bash
export TRANSDUCER_AUTH_TOKEN=your-secret-token
transducer --disable-spiffe --orchestrator-url http://orchestrator:4003
```

### No Authentication

For local development only:

```bash
transducer --disable-spiffe --orchestrator-url http://localhost:4003
```

## Protocol

Transducer uses gRPC to communicate with the orchestrator. Key RPCs:

| RPC | Description |
|-----|-------------|
| `Register` | Register capabilities with orchestrator |
| `Heartbeat` | Bidirectional stream for health monitoring |
| `ReceiveWork` | Server-push stream of work assignments |
| `ReportProgress` | Report execution progress mid-flight |
| `SubmitResult` | Submit completed work results |
| `Deregister` | Graceful shutdown |

See [transducer-api](https://github.com/coproduct/transducer-api) for protocol definitions.

## Configuration

### Claude Sandbox Settings

The `config/settings.json` file configures Claude Code permissions:

```json
{
  "permissions": {
    "allow": ["Bash(git *)", "Read", "Edit", "Write(/workspaces/**)"],
    "deny": ["Bash(curl *)", "Write(/etc/**)"]
  },
  "sandbox": {
    "filesystem": { "allow": ["/workspaces"], "deny": ["/etc"] },
    "network": { "allow": ["api.anthropic.com:443"], "deny": ["*"] }
  }
}
```

## Security

- **Container Isolation**: Docker provides process/network isolation
- **SPIFFE mTLS**: Cryptographic workload identity
- **Bubblewrap Sandboxing**: Claude Code runs in a sandboxed environment
- **Non-root Execution**: Container runs as unprivileged user
- **Read-only Filesystem**: Only `/tmp` and `/workspaces` are writable

## Related Projects

- [transducer-api](https://github.com/coproduct/transducer-api) - Protocol definitions

## License

MIT OR Apache-2.0
