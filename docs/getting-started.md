# Getting Started with Sentinel Agent Python SDK

This guide will walk you through creating your first Sentinel agent in Python.

## Prerequisites

- Python 3.10 or later
- A running Sentinel proxy instance (or just the SDK for development)

## Installation

```bash
pip install sentinel-agent-sdk
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add sentinel-agent-sdk
```

## Your First Agent

Create a new file `my_agent.py`:

```python
from sentinel_agent_sdk import Agent, Decision, Request, run_agent


class MyAgent(Agent):
    @property
    def name(self) -> str:
        return "my-agent"

    async def on_request(self, request: Request) -> Decision:
        # Block requests to /admin paths
        if request.path_starts_with("/admin"):
            return Decision.deny().with_body("Access denied")

        # Allow all other requests
        return Decision.allow()


if __name__ == "__main__":
    run_agent(MyAgent())
```

## Running Your Agent

```bash
python my_agent.py --socket /tmp/my-agent.sock
```

Your agent is now listening on `/tmp/my-agent.sock` and ready to receive events from Sentinel.

## Understanding the Agent Class

The `Agent` base class defines the hooks you can implement:

```python
from sentinel_agent_sdk import Agent, Decision, Request, Response


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

## Making Decisions

The `Decision` builder provides a fluent API:

```python
# Allow the request
Decision.allow()

# Block with 403 Forbidden
Decision.deny()

# Block with custom status
Decision.block(429).with_body("Too many requests")

# Block with JSON body
Decision.block(400).with_json_body({"error": "Invalid request"})

# Redirect
Decision.redirect("/login")
Decision.redirect_permanent("/new-path")

# Allow with header modifications
Decision.allow() \
    .add_request_header("X-User-ID", "12345") \
    .add_response_header("X-Cache", "HIT") \
    .remove_response_header("Server")

# Add audit metadata
Decision.deny() \
    .with_tag("security") \
    .with_rule_id("ADMIN-001") \
    .with_confidence(0.95) \
    .with_metadata("reason", "blocked by rule")
```

## Working with Requests

The `Request` type provides convenient methods:

```python
async def on_request(self, request: Request) -> Decision:
    # Path inspection
    path = request.path
    if request.path_starts_with("/api/"):
        pass
    if request.path_equals("/health"):
        return Decision.allow()

    # Headers (case-insensitive)
    auth = request.get_header("Authorization")
    if not request.has_header("X-API-Key"):
        return Decision.unauthorized()

    # Common headers as properties
    user_agent = request.user_agent
    content_type = request.content_type
    host = request.host

    # Query parameters
    page = request.query_params.get("page", ["1"])[0]

    # Request metadata
    client_ip = request.client_ip
    method = request.method
    correlation_id = request.correlation_id

    # Body (when body inspection is enabled)
    if request.body:
        data = request.body.decode("utf-8")

    return Decision.allow()
```

## Working with Responses

Inspect upstream responses:

```python
async def on_response(self, request: Request, response: Response) -> Decision:
    # Check status code
    if response.status_code >= 500:
        return Decision.allow().with_tag("upstream-error")

    # Inspect headers
    content_type = response.get_header("Content-Type")

    # Add security headers
    return (
        Decision.allow()
        .add_response_header("X-Frame-Options", "DENY")
        .add_response_header("X-Content-Type-Options", "nosniff")
        .remove_response_header("Server")
    )
```

## Typed Configuration

For agents with configuration, use `ConfigurableAgent`:

```python
from dataclasses import dataclass
from sentinel_agent_sdk import ConfigurableAgent, Decision, Request


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

## Connecting to Sentinel

Configure Sentinel to use your agent:

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

## CLI Options

The SDK provides built-in CLI argument parsing:

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
| `--socket PATH` | Unix socket path | `/tmp/sentinel-agent.sock` |
| `--log-level LEVEL` | DEBUG, INFO, WARNING, ERROR | `INFO` |
| `--json-logs` | Output logs as JSON | disabled |

## Programmatic Runner

For more control, use `AgentRunner` directly:

```python
import asyncio
from pathlib import Path
from sentinel_agent_sdk import AgentRunner


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

## Request Logging

Use `on_request_complete` for logging and metrics:

```python
async def on_request_complete(
    self,
    request: Request,
    status: int,
    duration_ms: int,
) -> None:
    print(
        f"{request.client_ip} - {request.method} {request.path} "
        f"-> {status} ({duration_ms}ms)"
    )
```

## Error Handling

Return appropriate decisions for errors:

```python
import jwt

async def on_request(self, request: Request) -> Decision:
    auth = request.authorization
    if not auth or not auth.startswith("Bearer "):
        return (
            Decision.unauthorized()
            .with_body("Missing or invalid Authorization header")
            .with_tag("auth-missing")
        )

    token = auth[7:]  # Remove "Bearer " prefix

    try:
        payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        return (
            Decision.allow()
            .add_request_header("X-User-ID", payload.get("sub", ""))
        )
    except jwt.ExpiredSignatureError:
        return (
            Decision.unauthorized()
            .with_body("Token expired")
            .with_tag("auth-expired")
        )
    except jwt.InvalidTokenError:
        return (
            Decision.unauthorized()
            .with_body("Invalid token")
            .with_tag("auth-invalid")
        )
```

## Testing Your Agent

Write tests using pytest:

```python
import pytest
from my_agent import MyAgent
from sentinel_agent_sdk import Request


@pytest.mark.asyncio
async def test_blocks_admin_path():
    agent = MyAgent()
    request = Request.builder().path("/admin/users").build()

    decision = await agent.on_request(request)

    assert decision.is_block()


@pytest.mark.asyncio
async def test_allows_public_path():
    agent = MyAgent()
    request = Request.builder().path("/public/docs").build()

    decision = await agent.on_request(request)

    assert decision.is_allow()
```

Run tests:

```bash
pytest
# Or with coverage
pytest --cov=my_agent
```

## Next Steps

- Read the [API Reference](api.md) for complete documentation
- Browse [Examples](examples.md) for common patterns
- See the [Configuration](configuration.md) guide for Sentinel setup

## Need Help?

- [GitHub Issues](https://github.com/raskell-io/sentinel-agent-python-sdk/issues)
- [Sentinel Documentation](https://sentinel.raskell.io/docs)
