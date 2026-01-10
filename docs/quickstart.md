# Quickstart Guide

This guide will help you create your first Sentinel agent in under 5 minutes.

## Prerequisites

- Python 3.10+
- Sentinel proxy (for testing with real traffic)

## Step 1: Install the SDK

```bash
pip install sentinel-agent-sdk
```

## Step 2: Create Your Agent

Create a file called `my_agent.py`:

```python
#!/usr/bin/env python3
from sentinel_agent_sdk import Agent, Decision, Request, run_agent


class MyAgent(Agent):
    """My first Sentinel agent."""

    @property
    def name(self) -> str:
        return "my-agent"

    async def on_request(self, request: Request) -> Decision:
        """Process each incoming request."""
        # Log the request
        print(f"Processing: {request.method} {request.path}")

        # Block requests to sensitive paths
        if request.path_starts_with("/admin"):
            return (
                Decision.deny()
                .with_body("Access denied")
                .with_tag("blocked")
            )

        # Allow with a custom header
        return (
            Decision.allow()
            .add_request_header("X-Processed-By", "my-agent")
        )


if __name__ == "__main__":
    run_agent(MyAgent())
```

## Step 3: Run the Agent

```bash
python my_agent.py --socket /tmp/my-agent.sock --log-level DEBUG
```

You should see:

```
2024-01-15 10:30:00 [my-agent] INFO: Agent 'my-agent' listening on /tmp/my-agent.sock
```

## Step 4: Configure Sentinel

Add the agent to your Sentinel configuration (`sentinel.kdl`):

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
        timeout-ms 100
        failure-mode "open"
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

## Step 5: Test It

With Sentinel running, send a test request:

```bash
# This should pass through
curl http://localhost:8080/api/users

# This should be blocked
curl http://localhost:8080/api/admin/settings
```

## Command Line Options

The `run_agent` function supports these CLI arguments:

| Option | Description | Default |
|--------|-------------|---------|
| `--socket PATH` | Unix socket path | `/tmp/sentinel-agent.sock` |
| `--log-level LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `--json-logs` | Enable JSON log format | disabled |

## Next Steps

- Read the [API Reference](api.md) for complete documentation
- See [Examples](examples.md) for common patterns
- Learn about [Sentinel Configuration](configuration.md) options
