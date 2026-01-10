# Sentinel Agent Python SDK

A Python SDK for building agents that integrate with the [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy.

## Installation

```bash
pip install sentinel-agent-sdk
```

Or install from source:

```bash
cd sentinel-agent-python-sdk

# Using mise + uv (recommended)
mise install
uv sync

# Or using pip
pip install -e .
```

## Quick Start

Create a simple agent that blocks requests to admin paths:

```python
from sentinel_agent_sdk import Agent, Decision, Request, run_agent


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

- **Simple API**: Implement the `Agent` class with intuitive handler methods
- **Fluent Decision Builder**: Chain methods to build complex responses
- **Request/Response Wrappers**: Ergonomic access to headers, body, and metadata
- **Typed Configuration**: Use `ConfigurableAgent` for type-safe configuration
- **Async Support**: Built on asyncio for high-performance concurrent processing
- **Protocol Compatible**: Full compatibility with Sentinel's agent protocol

## Core Concepts

### Agent

The `Agent` class is the main abstraction for building agents. Implement the handlers you need:

```python
class MyAgent(Agent):
    @property
    def name(self) -> str:
        """Required: Return agent name for logging."""
        return "my-agent"

    async def on_configure(self, config: dict) -> None:
        """Optional: Handle configuration from proxy."""
        pass

    async def on_request(self, request: Request) -> Decision:
        """Optional: Process request headers."""
        return Decision.allow()

    async def on_request_body(self, request: Request) -> Decision:
        """Optional: Process request body (when enabled)."""
        return Decision.allow()

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Optional: Process response headers."""
        return Decision.allow()

    async def on_response_body(self, request: Request, response: Response) -> Decision:
        """Optional: Process response body (when enabled)."""
        return Decision.allow()

    async def on_request_complete(self, request: Request, status: int, duration_ms: int) -> None:
        """Optional: Called when request processing completes."""
        pass
```

### Request

The `Request` class provides ergonomic access to HTTP request data:

```python
async def on_request(self, request: Request) -> Decision:
    # Method checks
    if request.is_get():
        pass
    if request.is_post():
        pass

    # Path access
    path = request.path           # Full path with query string
    path_only = request.path_only # Path without query string

    # Path matching
    if request.path_starts_with("/api"):
        pass
    if request.path_equals("/health"):
        pass

    # Query parameters
    page = request.query("page")           # Single value
    tags = request.query_all("tag")        # All values

    # Headers (case-insensitive)
    auth = request.header("Authorization")
    has_auth = request.has_header("Authorization")

    # Common headers
    host = request.host
    user_agent = request.user_agent
    content_type = request.content_type

    # Body access
    body_bytes = request.body
    body_str = request.body_str
    body_json = request.body_json()

    # Metadata
    client_ip = request.client_ip
    correlation_id = request.correlation_id

    return Decision.allow()
```

### Response

The `Response` class provides similar access for HTTP responses:

```python
async def on_response(self, request: Request, response: Response) -> Decision:
    # Status checks
    status = response.status_code
    if response.is_success():      # 2xx
        pass
    if response.is_redirect():     # 3xx
        pass
    if response.is_client_error(): # 4xx
        pass
    if response.is_server_error(): # 5xx
        pass
    if response.is_error():        # 4xx or 5xx
        pass

    # Headers
    content_type = response.content_type
    location = response.location  # For redirects

    # Content type checks
    if response.is_json():
        pass
    if response.is_html():
        pass

    # Body
    body_bytes = response.body
    body_str = response.body_str
    body_json = response.body_json()

    return Decision.allow()
```

### Decision

The `Decision` class provides a fluent API for building agent responses:

```python
# Basic decisions
Decision.allow()                    # Pass through
Decision.deny()                     # Block with 403
Decision.unauthorized()             # Block with 401
Decision.rate_limited()             # Block with 429
Decision.block(500)                 # Block with custom status
Decision.redirect("/login")         # Redirect (302)
Decision.redirect_permanent("/new") # Redirect (301)

# Customizing block responses
Decision.deny() \
    .with_body("Access denied") \
    .with_block_header("X-Blocked-Reason", "policy")

# JSON responses
Decision.block(400) \
    .with_json_body({"error": "Invalid request"})

# Header mutations
Decision.allow() \
    .add_request_header("X-Processed", "true") \
    .remove_request_header("X-Internal") \
    .add_response_header("X-Cache", "HIT") \
    .remove_response_header("Server")

# Audit metadata
Decision.deny() \
    .with_tag("security") \
    .with_tags(["blocked", "suspicious"]) \
    .with_rule_id("RULE_001") \
    .with_confidence(0.95) \
    .with_reason_code("RATE_EXCEEDED") \
    .with_metadata("client_ip", "1.2.3.4")
```

### Configurable Agent

For agents that need typed configuration:

```python
from dataclasses import dataclass
from sentinel_agent_sdk import ConfigurableAgent, Decision, Request


@dataclass
class MyConfig:
    rate_limit: int = 100
    enabled: bool = True
    blocked_paths: list[str] = None

    def __post_init__(self):
        if self.blocked_paths is None:
            self.blocked_paths = []


class MyAgent(ConfigurableAgent[MyConfig]):
    def __init__(self):
        super().__init__(MyConfig())

    @property
    def name(self) -> str:
        return "my-agent"

    async def on_config_applied(self, config: MyConfig) -> None:
        print(f"Config applied: rate_limit={config.rate_limit}")

    async def on_request(self, request: Request) -> Decision:
        if not self.config.enabled:
            return Decision.allow()

        for path in self.config.blocked_paths:
            if request.path_starts_with(path):
                return Decision.deny()

        return Decision.allow()
```

## Running Agents

### Command Line

```bash
# Basic usage
python my_agent.py --socket /tmp/my-agent.sock

# With JSON logs
python my_agent.py --socket /tmp/my-agent.sock --json-logs

# With debug logging
python my_agent.py --socket /tmp/my-agent.sock --log-level DEBUG
```

### Programmatic

```python
import asyncio
from pathlib import Path
from sentinel_agent_sdk import AgentRunner

async def main():
    runner = (
        AgentRunner(MyAgent())
        .with_name("my-agent")
        .with_socket(Path("/tmp/my-agent.sock"))
        .with_json_logs()
    )
    await runner.run()

asyncio.run(main())
```

## Sentinel Configuration

Configure Sentinel to use your agent:

```kdl
agents {
    agent "my-agent" {
        type "custom"
        transport "unix_socket" {
            path "/tmp/my-agent.sock"
        }
        events ["request_headers", "response_headers"]
        timeout_ms 1000
        failure_mode "open"

        config {
            rate_limit 100
            enabled true
            blocked_paths ["/admin", "/internal"]
        }
    }
}

routes {
    route "api" {
        matches { path_prefix "/api" }
        upstream "backend"
        agents ["my-agent"]
    }
}
```

## Examples

See the `examples/` directory for complete examples:

- `simple_agent.py` - Basic request filtering
- `configurable_agent.py` - Rate limiting with configuration
- `body_inspection_agent.py` - Request/response body inspection

## Protocol Compatibility

This SDK implements Sentinel's agent protocol version 1:

- Unix socket communication with length-prefixed JSON
- Support for all event types (request headers, body, response headers, body, complete)
- Full decision types (allow, block, redirect, challenge)
- Header mutations and audit metadata

## Development

This project uses [mise](https://mise.jdx.dev/) for tool management and [uv](https://github.com/astral-sh/uv) for fast Python package management.

```bash
# Install tools via mise
mise install

# Sync dependencies (creates .venv automatically)
uv sync --all-extras

# Run tests
uv run pytest

# Type checking
uv run mypy src

# Linting
uv run ruff check src

# Format code
uv run ruff format src
```

Alternatively, with standard pip:

```bash
pip install -e ".[dev]"
pytest
mypy src
ruff check src
```

## License

Apache License 2.0 - see LICENSE file for details.
