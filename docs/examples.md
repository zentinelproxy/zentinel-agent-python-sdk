# Examples

Common patterns and use cases for Zentinel agents.

## Basic Request Blocking

Block requests based on path patterns:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class BlockingAgent(Agent):
    """Block specific paths."""

    BLOCKED_PATHS = ["/admin", "/internal", "/.git", "/.env"]

    @property
    def name(self) -> str:
        return "blocking-agent"

    async def on_request(self, request: Request) -> Decision:
        for blocked in self.BLOCKED_PATHS:
            if request.path_starts_with(blocked):
                return (
                    Decision.deny()
                    .with_body("Not Found")
                    .with_tag("path-blocked")
                )
        return Decision.allow()
```

## IP-Based Access Control

Block or allow requests based on client IP:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class IPFilterAgent(Agent):
    """Allow only specific IP ranges."""

    ALLOWED_IPS = {"10.0.0.0/8", "192.168.0.0/16", "127.0.0.1"}

    @property
    def name(self) -> str:
        return "ip-filter"

    async def on_request(self, request: Request) -> Decision:
        client_ip = request.client_ip

        # Simple check (use ipaddress module for CIDR)
        if client_ip in self.ALLOWED_IPS:
            return Decision.allow()

        return (
            Decision.deny()
            .with_tag("ip-blocked")
            .with_metadata("blocked_ip", client_ip)
        )
```

## Authentication Validation

Validate JWT tokens:

```python
import jwt
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class AuthAgent(Agent):
    """Validate JWT authentication."""

    def __init__(self, secret: str):
        self.secret = secret

    @property
    def name(self) -> str:
        return "auth-agent"

    async def on_request(self, request: Request) -> Decision:
        # Skip auth for public paths
        if request.path_starts_with("/public"):
            return Decision.allow()

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
            # Add user info to request headers for upstream
            return (
                Decision.allow()
                .add_request_header("X-User-ID", payload.get("sub", ""))
                .add_request_header("X-User-Role", payload.get("role", ""))
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

## Rate Limiting

Simple in-memory rate limiting:

```python
import time
from collections import defaultdict
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class RateLimitAgent(Agent):
    """Simple rate limiting agent."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    @property
    def name(self) -> str:
        return "rate-limit"

    async def on_request(self, request: Request) -> Decision:
        key = request.client_ip
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old entries and add current
        self.requests[key] = [t for t in self.requests[key] if t > window_start]
        self.requests[key].append(now)

        if len(self.requests[key]) > self.max_requests:
            return (
                Decision.rate_limited()
                .with_body("Too many requests")
                .with_tag("rate-limited")
                .add_response_header("Retry-After", str(self.window_seconds))
            )

        # Add rate limit headers
        remaining = self.max_requests - len(self.requests[key])
        return (
            Decision.allow()
            .add_response_header("X-RateLimit-Limit", str(self.max_requests))
            .add_response_header("X-RateLimit-Remaining", str(remaining))
        )
```

## Header Modification

Add, remove, or modify headers:

```python
from zentinel_agent_sdk import Agent, Decision, Request, Response, run_agent


class HeaderAgent(Agent):
    """Modify request and response headers."""

    @property
    def name(self) -> str:
        return "header-agent"

    async def on_request(self, request: Request) -> Decision:
        return (
            Decision.allow()
            # Add headers for upstream
            .add_request_header("X-Forwarded-By", "zentinel")
            .add_request_header("X-Request-ID", request.correlation_id)
            # Remove sensitive headers
            .remove_request_header("X-Internal-Token")
        )

    async def on_response(self, request: Request, response: Response) -> Decision:
        return (
            Decision.allow()
            # Add security headers
            .add_response_header("X-Frame-Options", "DENY")
            .add_response_header("X-Content-Type-Options", "nosniff")
            .add_response_header("X-XSS-Protection", "1; mode=block")
            # Remove server info
            .remove_response_header("Server")
            .remove_response_header("X-Powered-By")
        )
```

## Configurable Agent

Agent with runtime configuration:

```python
from dataclasses import dataclass
from zentinel_agent_sdk import ConfigurableAgent, Decision, Request, run_agent


@dataclass
class Config:
    enabled: bool = True
    blocked_paths: list[str] = None
    log_requests: bool = False

    def __post_init__(self):
        if self.blocked_paths is None:
            self.blocked_paths = ["/admin"]


class ConfigurableBlocker(ConfigurableAgent[Config]):
    """Agent with runtime configuration."""

    def __init__(self):
        super().__init__(Config())

    @property
    def name(self) -> str:
        return "configurable-blocker"

    async def on_config_applied(self, config: Config) -> None:
        print(f"Configuration updated: enabled={config.enabled}")

    async def on_request(self, request: Request) -> Decision:
        if not self.config.enabled:
            return Decision.allow()

        if self.config.log_requests:
            print(f"Request: {request.method} {request.path}")

        for blocked in self.config.blocked_paths:
            if request.path_starts_with(blocked):
                return Decision.deny()

        return Decision.allow()
```

## Request Logging

Log all requests with timing:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class LoggingAgent(Agent):
    """Log all requests."""

    @property
    def name(self) -> str:
        return "logging-agent"

    async def on_request(self, request: Request) -> Decision:
        return (
            Decision.allow()
            .with_tag(f"method:{request.method.lower()}")
            .with_metadata("path", request.path)
            .with_metadata("client_ip", request.client_ip)
        )

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

## Content-Type Validation

Validate request content types:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class ContentTypeAgent(Agent):
    """Validate content types for POST/PUT requests."""

    ALLOWED_TYPES = {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }

    @property
    def name(self) -> str:
        return "content-type-validator"

    async def on_request(self, request: Request) -> Decision:
        # Only check methods with body
        if request.method not in ("POST", "PUT", "PATCH"):
            return Decision.allow()

        content_type = request.content_type
        if not content_type:
            return (
                Decision.block(400)
                .with_body("Content-Type header required")
            )

        # Check against allowed types (ignore params like charset)
        base_type = content_type.split(";")[0].strip().lower()
        if base_type not in self.ALLOWED_TYPES:
            return (
                Decision.block(415)
                .with_body(f"Unsupported Content-Type: {base_type}")
                .with_tag("invalid-content-type")
            )

        return Decision.allow()
```

## Redirect Agent

Redirect requests to different URLs:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class RedirectAgent(Agent):
    """Redirect old paths to new locations."""

    REDIRECTS = {
        "/old-path": "/new-path",
        "/legacy": "/v2/api",
        "/blog": "https://blog.example.com",
    }

    @property
    def name(self) -> str:
        return "redirect-agent"

    async def on_request(self, request: Request) -> Decision:
        if request.path in self.REDIRECTS:
            new_location = self.REDIRECTS[request.path]
            return Decision.redirect(new_location)

        # Redirect HTTP to HTTPS
        if request.headers.get("x-forwarded-proto", [""])[0] == "http":
            https_url = f"https://{request.host}{request.uri}"
            return Decision.redirect_permanent(https_url)

        return Decision.allow()
```

## Combining Multiple Checks

Agent that performs multiple validations:

```python
from zentinel_agent_sdk import Agent, Decision, Request, run_agent


class SecurityAgent(Agent):
    """Comprehensive security checks."""

    @property
    def name(self) -> str:
        return "security-agent"

    async def on_request(self, request: Request) -> Decision:
        # Check 1: User-Agent required
        if not request.user_agent:
            return Decision.block(400).with_body("User-Agent required")

        # Check 2: Block suspicious paths
        suspicious = ["/..", "/etc/", "/proc/", ".php"]
        for pattern in suspicious:
            if pattern in request.path.lower():
                return (
                    Decision.deny()
                    .with_tag("path-traversal")
                    .with_rule_id("SEC-001")
                )

        # Check 3: Block large requests without content-length
        if request.method in ("POST", "PUT"):
            if not request.has_header("content-length"):
                return Decision.block(411).with_body("Content-Length required")

        # All checks passed
        return (
            Decision.allow()
            .with_tag("security-passed")
            .add_response_header("X-Security-Check", "passed")
        )
```
