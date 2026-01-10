#!/usr/bin/env python3
"""Simple Sentinel agent example.

This example demonstrates a basic agent that:
- Blocks requests to /admin paths
- Adds custom headers to allowed requests
- Logs request completions
"""

from sentinel_agent_sdk import Agent, Decision, Request, Response, run_agent


class SimpleAgent(Agent):
    """A simple example agent that blocks admin paths."""

    @property
    def name(self) -> str:
        return "simple-agent"

    async def on_request(self, request: Request) -> Decision:
        """Process incoming requests."""
        # Block admin paths
        if request.path_starts_with("/admin"):
            return (
                Decision.deny()
                .with_body("Access denied")
                .with_tag("security")
                .with_rule_id("ADMIN_BLOCKED")
            )

        # Block requests without User-Agent
        if not request.user_agent:
            return (
                Decision.block(400)
                .with_body("User-Agent header required")
                .with_tag("validation")
            )

        # Allow with custom header
        return Decision.allow().add_request_header("X-Agent-Processed", "true")

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Process responses."""
        # Add timing header
        return Decision.allow().add_response_header("X-Processed-By", self.name)

    async def on_request_complete(
        self,
        request: Request,
        status: int,
        duration_ms: int,
    ) -> None:
        """Log completed requests."""
        print(f"Request completed: {request.method} {request.path} -> {status} ({duration_ms}ms)")


if __name__ == "__main__":
    run_agent(SimpleAgent())
