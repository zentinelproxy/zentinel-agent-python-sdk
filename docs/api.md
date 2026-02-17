# API Reference

## Agent

The base class for all Zentinel agents.

```python
from zentinel_agent_sdk import Agent
```

### Abstract Properties

#### `name`

```python
@property
@abstractmethod
def name(self) -> str: ...
```

Returns the agent identifier used for logging.

### Event Handlers

#### `on_configure`

```python
async def on_configure(self, config: dict[str, Any]) -> None: ...
```

Called when the agent receives configuration from the proxy. Override to validate and store configuration.

#### `on_request`

```python
async def on_request(self, request: Request) -> Decision: ...
```

Called when request headers are received. This is the main entry point for request processing.

**Default**: Returns `Decision.allow()`

#### `on_request_body`

```python
async def on_request_body(self, request: Request) -> Decision: ...
```

Called when the request body is available (requires body inspection to be enabled in Zentinel).

**Default**: Returns `Decision.allow()`

#### `on_response`

```python
async def on_response(self, request: Request, response: Response) -> Decision: ...
```

Called when response headers are received from the upstream server.

**Default**: Returns `Decision.allow()`

#### `on_response_body`

```python
async def on_response_body(self, request: Request, response: Response) -> Decision: ...
```

Called when the response body is available (requires body inspection to be enabled).

**Default**: Returns `Decision.allow()`

#### `on_request_complete`

```python
async def on_request_complete(
    self,
    request: Request,
    status: int,
    duration_ms: int,
) -> None: ...
```

Called when request processing is complete. Use for logging or metrics.

---

## ConfigurableAgent

A generic agent class with typed configuration support.

```python
from zentinel_agent_sdk import ConfigurableAgent
from dataclasses import dataclass

@dataclass
class MyConfig:
    rate_limit: int = 100
    enabled: bool = True

class MyAgent(ConfigurableAgent[MyConfig]):
    def __init__(self):
        super().__init__(MyConfig())

    @property
    def name(self) -> str:
        return "my-agent"

    async def on_request(self, request: Request) -> Decision:
        if not self.config.enabled:
            return Decision.allow()
        # Use self.config.rate_limit...
        return Decision.allow()
```

### Properties

#### `config`

```python
@property
def config(self) -> T: ...
```

Returns the current configuration instance.

### Methods

#### `parse_config`

```python
def parse_config(self, config_dict: dict[str, Any]) -> T: ...
```

Override to customize config parsing. Default works with dataclasses and Pydantic models.

#### `on_config_applied`

```python
async def on_config_applied(self, config: T) -> None: ...
```

Called after new configuration is applied.

---

## Decision

Fluent builder for agent decisions.

```python
from zentinel_agent_sdk import Decision
```

### Factory Methods

#### `Decision.allow()`

Create an allow decision (pass request through).

```python
return Decision.allow()
```

#### `Decision.block(status=403)`

Create a block decision with a status code.

```python
return Decision.block(403)
return Decision.block(500)
```

#### `Decision.deny()`

Shorthand for `Decision.block(403)`.

```python
return Decision.deny()
```

#### `Decision.unauthorized()`

Shorthand for `Decision.block(401)`.

```python
return Decision.unauthorized()
```

#### `Decision.rate_limited()`

Shorthand for `Decision.block(429)`.

```python
return Decision.rate_limited()
```

#### `Decision.redirect(url, status=302)`

Create a redirect decision.

```python
return Decision.redirect("https://example.com/login")
return Decision.redirect("https://example.com/new-path", 301)
```

#### `Decision.redirect_permanent(url)`

Shorthand for `Decision.redirect(url, 301)`.

```python
return Decision.redirect_permanent("https://example.com/new-path")
```

#### `Decision.challenge(challenge_type, params=None)`

Create a challenge decision (e.g., CAPTCHA).

```python
return Decision.challenge("captcha", {"site_key": "..."})
```

### Chaining Methods

All methods return `self` for chaining.

#### `with_body(body)`

Set the response body for block decisions.

```python
Decision.deny().with_body("Access denied")
```

#### `with_json_body(value)`

Set a JSON response body. Automatically sets `Content-Type: application/json`.

```python
Decision.block(400).with_json_body({"error": "Invalid request"})
```

#### `with_block_header(name, value)`

Add a header to the block response.

```python
Decision.deny().with_block_header("X-Blocked-By", "my-agent")
```

#### `add_request_header(name, value)`

Add a header to the upstream request.

```python
Decision.allow().add_request_header("X-User-ID", "123")
```

#### `remove_request_header(name)`

Remove a header from the upstream request.

```python
Decision.allow().remove_request_header("Cookie")
```

#### `add_response_header(name, value)`

Add a header to the client response.

```python
Decision.allow().add_response_header("X-Frame-Options", "DENY")
```

#### `remove_response_header(name)`

Remove a header from the client response.

```python
Decision.allow().remove_response_header("Server")
```

### Audit Methods

#### `with_tag(tag)`

Add an audit tag.

```python
Decision.deny().with_tag("security")
```

#### `with_tags(tags)`

Add multiple audit tags.

```python
Decision.deny().with_tags(["blocked", "rate-limit"])
```

#### `with_rule_id(rule_id)`

Add a rule ID for audit logging.

```python
Decision.deny().with_rule_id("SQLI-001")
```

#### `with_confidence(confidence)`

Set a confidence score (0.0 to 1.0).

```python
Decision.deny().with_confidence(0.95)
```

#### `with_reason_code(code)`

Add a reason code.

```python
Decision.deny().with_reason_code("IP_BLOCKED")
```

#### `with_metadata(key, value)`

Add custom audit metadata.

```python
Decision.deny().with_metadata("blocked_ip", "192.168.1.100")
```

---

## Request

Represents an incoming HTTP request.

```python
from zentinel_agent_sdk import Request
```

### Properties

#### `method`

The HTTP method (GET, POST, etc.).

```python
if request.method == "POST":
    ...
```

#### `path`

The request path without query string.

```python
path = request.path  # "/api/users"
```

#### `uri`

The full URI including query string.

```python
uri = request.uri  # "/api/users?page=1"
```

#### `query_string`

The raw query string.

```python
qs = request.query_string  # "page=1&limit=10"
```

#### `headers`

Dictionary of headers (lowercase keys, list values).

```python
content_type = request.headers.get("content-type", [""])[0]
```

#### `body`

The request body as bytes (if body inspection is enabled).

```python
if request.body:
    data = json.loads(request.body)
```

### Convenience Methods

#### `path_starts_with(prefix)`

Check if the path starts with a prefix.

```python
if request.path_starts_with("/api/"):
    ...
```

#### `path_equals(path)`

Check if the path exactly matches.

```python
if request.path_equals("/health"):
    ...
```

#### `has_header(name)`

Check if a header exists (case-insensitive).

```python
if request.has_header("Authorization"):
    ...
```

#### `get_header(name)`

Get a header value (first value if multiple).

```python
auth = request.get_header("authorization")
```

#### `query_params`

Parsed query parameters as a dictionary.

```python
page = request.query_params.get("page", ["1"])[0]
```

### Common Header Properties

```python
request.host           # Host header
request.user_agent     # User-Agent header
request.content_type   # Content-Type header
request.authorization  # Authorization header
```

### Metadata Properties

```python
request.correlation_id  # Request correlation ID
request.request_id      # Unique request ID
request.client_ip       # Client IP address
request.client_port     # Client port
request.server_name     # Server name
request.protocol        # HTTP protocol version
request.timestamp       # Request timestamp
```

---

## Response

Represents an HTTP response from the upstream.

```python
from zentinel_agent_sdk import Response
```

### Properties

#### `status_code`

The HTTP status code.

```python
if response.status_code == 200:
    ...
```

#### `headers`

Dictionary of response headers.

```python
content_type = response.headers.get("content-type", [""])[0]
```

#### `body`

The response body as bytes (if body inspection is enabled).

```python
if response.body:
    data = json.loads(response.body)
```

### Convenience Methods

#### `has_header(name)`

Check if a header exists.

#### `get_header(name)`

Get a header value.

---

## AgentRunner

Runner for starting and managing an agent.

```python
from zentinel_agent_sdk import AgentRunner
```

### Usage

```python
runner = (
    AgentRunner(MyAgent())
    .with_socket("/tmp/my-agent.sock")
    .with_log_level("DEBUG")
)

await runner.run()
```

### Builder Methods

#### `with_name(name)`

Set the agent name for logging.

#### `with_socket(path)`

Set the Unix socket path.

#### `with_json_logs()`

Enable JSON log format.

#### `with_log_level(level)`

Set the log level (DEBUG, INFO, WARNING, ERROR).

---

## run_agent

Convenience function to run an agent with CLI argument parsing.

```python
from zentinel_agent_sdk import run_agent

if __name__ == "__main__":
    run_agent(MyAgent())
```

This parses `--socket`, `--log-level`, and `--json-logs` from command line arguments.
