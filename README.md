<div align="center">

<h1 align="center">
  Zentinel Agent Python SDK
</h1>

<p align="center">
  <em>Build agents that extend Zentinel's security and policy capabilities.</em><br>
  <em>Inspect, block, redirect, and transform HTTP traffic.</em>
</p>

<p align="center">
  <a href="https://www.python.org/">
    <img alt="Python" src="https://img.shields.io/badge/Python-3.10+-3776ab?logo=python&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/zentinelproxy/zentinel">
    <img alt="Zentinel" src="https://img.shields.io/badge/Built%20for-Zentinel-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="docs/index.md">Documentation</a> •
  <a href="docs/quickstart.md">Quickstart</a> •
  <a href="docs/api.md">API Reference</a> •
  <a href="docs/examples.md">Examples</a>
</p>

</div>

---

The Zentinel Agent Python SDK provides a simple, async-first API for building agents that integrate with the [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Agents can inspect requests and responses, block malicious traffic, add headers, and attach audit metadata—all from Python.

## Quick Start

```bash
pip install zentinel-agent-sdk
```

Create `my_agent.py`:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class MyAgent(Agent):
    @property
    def name(self) -> str:
        return "my-agent"

    async def on_request(self, request: Request) -> Decision:
        if request.path_starts_with("/admin"):
            return Decision.deny().with_body("Access denied")
        return Decision.allow()


if __name__ == "__main__":
    run_agent(MyAgent())
```

Run the agent:

```bash
python my_agent.py --socket /tmp/my-agent.sock
```

## Features

| Feature | Description |
|---------|-------------|
| **Simple Agent API** | Implement `on_request`, `on_response`, and other hooks |
| **Fluent Decision Builder** | Chain methods: `Decision.deny().with_body(...).with_tag(...)` |
| **Request/Response Wrappers** | Ergonomic access to headers, body, query params, metadata |
| **Typed Configuration** | Generic `ConfigurableAgent[T]` with dataclass/Pydantic support |
| **Async Native** | Built on asyncio for high-performance concurrent processing |
| **Protocol Compatible** | Full compatibility with Zentinel agent protocol v1 |

## Why Agents?

Zentinel's agent system moves complex logic **out of the proxy core** and into isolated, testable, independently deployable processes:

- **Security isolation** — WAF engines, auth validation, and custom logic run in separate processes
- **Language flexibility** — Write agents in Python, Rust, Go, or any language
- **Independent deployment** — Update agent logic without restarting the proxy
- **Failure boundaries** — Agent crashes don't take down the dataplane

Agents communicate with Zentinel over Unix sockets using a simple length-prefixed JSON protocol.

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client    │────────▶│   Zentinel   │────────▶│   Upstream   │
└─────────────┘         └──────────────┘         └──────────────┘
                               │
                               │ Unix Socket (JSON)
                               ▼
                        ┌──────────────┐
                        │    Agent     │
                        │   (Python)   │
                        └──────────────┘
```

1. Client sends request to Zentinel
2. Zentinel forwards request headers to agent
3. Agent returns decision (allow, block, redirect) with optional header mutations
4. Zentinel applies the decision
5. Agent can also inspect response headers before they reach the client

---

## Core Concepts

### Agent

The `Agent` base class defines the hooks you can implement:

```python
from zentinel_agent_sdk import Agent, Decision, Request, Response


class MyAgent(Agent):
    @property
    def name(self) -> str:
        """Required: Agent identifier for logging."""
        return "my-agent"

    async def on_request(self, request: Request) -> Decision:
        """Called when request headers arrive."""
        return Decision.allow()

    async def on_request_body(self, request: Request) -> Decision:
        """Called when request body is available (if body inspection enabled)."""
        return Decision.allow()

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Called when response headers arrive from upstream."""
        return Decision.allow()

    async def on_response_body(self, request: Request, response: Response) -> Decision:
        """Called when response body is available (if body inspection enabled)."""
        return Decision.allow()

    async def on_request_complete(self, request: Request, status: int, duration_ms: int) -> None:
        """Called when request processing completes. Use for logging/metrics."""
        pass
```

### Request

Access HTTP request data with convenience methods:

```python
async def on_request(self, request: Request) -> Decision:
    # Path matching
    if request.path_starts_with("/api/"):
        pass
    if request.path_equals("/health"):
        return Decision.allow()

    # Headers (case-insensitive)
    auth = request.get_header("authorization")
    if not request.has_header("x-api-key"):
        return Decision.unauthorized()

    # Common headers as properties
    host = request.host
    user_agent = request.user_agent
    content_type = request.content_type

    # Query parameters
    page = request.query_params.get("page", ["1"])[0]

    # Request metadata
    client_ip = request.client_ip
    correlation_id = request.correlation_id

    # Body (when body inspection is enabled)
    if request.body:
        data = request.body.decode("utf-8")

    return Decision.allow()
```

### Response

Inspect upstream responses before they reach the client:

```python
async def on_response(self, request: Request, response: Response) -> Decision:
    # Status code
    if response.status_code >= 500:
        return Decision.allow().with_tag("upstream-error")

    # Headers
    content_type = response.get_header("content-type")

    # Add security headers to all responses
    return (
        Decision.allow()
        .add_response_header("X-Frame-Options", "DENY")
        .add_response_header("X-Content-Type-Options", "nosniff")
        .remove_response_header("Server")
    )
```

### Decision

Build responses with a fluent API:

```python
# Allow the request
Decision.allow()

# Block with common status codes
Decision.deny()           # 403 Forbidden
Decision.unauthorized()   # 401 Unauthorized
Decision.rate_limited()   # 429 Too Many Requests
Decision.block(503)       # Custom status

# Block with response body
Decision.deny().with_body("Access denied")
Decision.block(400).with_json_body({"error": "Invalid request"})

# Redirect
Decision.redirect("/login")                    # 302 temporary
Decision.redirect("/new-path", status=301)     # 301 permanent
Decision.redirect_permanent("/new-path")       # 301 permanent

# Modify headers
Decision.allow() \
    .add_request_header("X-User-ID", user_id) \
    .remove_request_header("Cookie") \
    .add_response_header("X-Cache", "HIT") \
    .remove_response_header("X-Powered-By")

# Audit metadata (appears in Zentinel logs)
Decision.deny() \
    .with_tag("blocked") \
    .with_rule_id("SQLI-001") \
    .with_confidence(0.95) \
    .with_metadata("matched_pattern", pattern)
```

### ConfigurableAgent

For agents with typed configuration:

```python
from dataclasses import dataclass
from zentinel_agent_sdk import ConfigurableAgent, Decision, Request


@dataclass
class RateLimitConfig:
    requests_per_minute: int = 60
    enabled: bool = True


class RateLimitAgent(ConfigurableAgent[RateLimitConfig]):
    def __init__(self):
        super().__init__(RateLimitConfig())

    @property
    def name(self) -> str:
        return "rate-limiter"

    async def on_config_applied(self, config: RateLimitConfig) -> None:
        print(f"Rate limit set to {config.requests_per_minute}/min")

    async def on_request(self, request: Request) -> Decision:
        if not self.config.enabled:
            return Decision.allow()
        # Use self.config.requests_per_minute...
        return Decision.allow()
```

---

## Running Agents

### Command Line

The `run_agent` helper parses CLI arguments:

```bash
# Basic usage
python my_agent.py --socket /tmp/my-agent.sock

# With options
python my_agent.py \
    --socket /tmp/my-agent.sock \
    --log-level DEBUG \
    --json-logs
```

| Option | Description | Default |
|--------|-------------|---------|
| `--socket PATH` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `--log-level LEVEL` | DEBUG, INFO, WARNING, ERROR | `INFO` |
| `--json-logs` | Output logs as JSON | disabled |

### Programmatic

```python
import asyncio
from pathlib import Path
from zentinel_agent_sdk import AgentRunner


async def main():
    runner = (
        AgentRunner(MyAgent())
        .with_socket(Path("/tmp/my-agent.sock"))
        .with_log_level("DEBUG")
        .with_json_logs()
    )
    await runner.run()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Zentinel Configuration

Configure Zentinel to connect to your agent:

```kdl
agents {
    agent "my-agent" type="custom" {
        unix-socket path="/tmp/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "open"
    }
}

filters {
    filter "my-filter" {
        type "agent"
        agent "my-agent"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "my-filter"
    }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `unix-socket path="..."` | Path to agent's Unix socket | required |
| `events` | Events to send: `request_headers`, `request_body`, `response_headers`, `response_body` | `request_headers` |
| `timeout-ms` | Timeout for agent calls | `1000` |
| `failure-mode` | `"open"` (allow on failure) or `"closed"` (block on failure) | `"open"` |

See [docs/configuration.md](docs/configuration.md) for complete configuration reference.

---

## Examples

The `examples/` directory contains complete, runnable examples:

| Example | Description |
|---------|-------------|
| [`simple_agent.py`](examples/simple_agent.py) | Basic request blocking and header modification |
| [`configurable_agent.py`](examples/configurable_agent.py) | Rate limiting with typed configuration |
| [`body_inspection_agent.py`](examples/body_inspection_agent.py) | Request and response body inspection |

See [docs/examples.md](docs/examples.md) for more patterns: authentication, rate limiting, IP filtering, header transformation, and more.

---

## Development

This project uses [mise](https://mise.jdx.dev/) for tool management and [uv](https://docs.astral.sh/uv/) for Python package management.

```bash
# Install tools
mise install

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=zentinel_agent_sdk

# Type checking
uv run mypy src

# Linting
uv run ruff check src

# Format code
uv run ruff format src
```

### Without mise/uv

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

### Project Structure

```
zentinel-agent-python-sdk/
├── src/zentinel_agent_sdk/
│   ├── __init__.py      # Public API exports
│   ├── agent.py         # Agent and ConfigurableAgent base classes
│   ├── decision.py      # Decision builder
│   ├── protocol.py      # Wire protocol types and encoding
│   ├── request.py       # Request wrapper
│   ├── response.py      # Response wrapper
│   └── runner.py        # AgentRunner and CLI handling
├── tests/
│   ├── test_sdk.py                    # Unit tests
│   ├── test_protocol_conformance.py   # Protocol compatibility tests
│   └── integration/                   # Integration tests
├── examples/                          # Example agents
└── docs/                              # Documentation
```

---

## Protocol

This SDK implements Zentinel Agent Protocol v1:

- **Transport**: Unix domain sockets (UDS) or gRPC
- **Encoding**: Length-prefixed JSON (4-byte big-endian length prefix) for UDS
- **Max message size**: 10 MB
- **Events**: `configure`, `request_headers`, `request_body_chunk`, `response_headers`, `response_body_chunk`, `request_complete`, `websocket_frame`, `guardrail_inspect`
- **Decisions**: `allow`, `block`, `redirect`, `challenge`

The protocol is designed for low latency and high throughput, with support for streaming body inspection.

For the canonical protocol specification, see the [Zentinel Agent Protocol documentation](https://github.com/zentinelproxy/zentinel/tree/main/crates/agent-protocol).

---

## Community

- 🐛 [Issues](https://github.com/zentinelproxy/zentinel-agent-python-sdk/issues) — Bug reports and feature requests
- 💬 [Zentinel Discussions](https://github.com/zentinelproxy/zentinel/discussions) — Questions and ideas
- 📖 [Zentinel Documentation](https://zentinelproxy.io/docs) — Proxy documentation

Contributions welcome. Please open an issue to discuss significant changes before submitting a PR.

---

## License

Apache 2.0 — See [LICENSE](LICENSE).
