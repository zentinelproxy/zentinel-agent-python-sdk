"""A v2 agent demonstrating protocol v2 features.

This agent uses the v2 protocol with:
- Capability negotiation
- gRPC transport
- Health reporting
- Streaming body support
"""

import asyncio
import logging

from zentinel_agent_sdk import Decision, Request, Response
from zentinel_agent_sdk.v2 import AgentCapabilities, AgentRunnerV2, AgentV2, HealthStatus

logger = logging.getLogger(__name__)


class V2Agent(AgentV2):
    """Example v2 agent with full protocol support."""

    @property
    def name(self) -> str:
        return "v2-agent"

    def capabilities(self) -> AgentCapabilities:
        """Define agent capabilities for v2 handshake."""
        return (
            AgentCapabilities("v2-agent", "V2 Example Agent", "1.0.0")
            # Enable streaming body support for large requests
            .with_streaming_body(True)
            # Support flow control for backpressure
            .with_flow_control(True)
            # Handle up to 100 concurrent requests
            .with_concurrent_requests(100)
            # Enable health reporting
            .with_health_reporting(True)
            # Set max body size to 10MB
            .with_max_body_size(10 * 1024 * 1024)
            # Set preferred chunk size for streaming
            .with_preferred_chunk_size(64 * 1024)
        )

    def health_status(self) -> HealthStatus:
        """Report current health status."""
        return HealthStatus.healthy(self.capabilities().agent_id)

    async def on_request(self, request: Request) -> Decision:
        """Process incoming requests."""
        logger.info(f"Processing v2 request: {request.method()} {request.path()}")

        # Block requests to /blocked
        if request.path_starts_with("/blocked"):
            return (
                Decision.deny()
                .with_body("This path is blocked by v2 agent")
                .with_tag("blocked-path")
            )

        # Require auth for /api paths
        if request.path_starts_with("/api") and request.header("authorization") is None:
            return Decision.unauthorized().with_body("Authorization required")

        # Allow other requests
        return (
            Decision.allow()
            .add_request_header("X-Processed-By", "v2-agent")
            .add_request_header("X-Protocol-Version", "2")
        )

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Process responses."""
        # Add security headers to HTML responses
        if response.is_html():
            return (
                Decision.allow()
                .add_response_header("X-Content-Type-Options", "nosniff")
                .add_response_header("X-Frame-Options", "DENY")
            )
        return Decision.allow()


if __name__ == "__main__":
    # Run with gRPC transport on port 50051
    runner = (
        AgentRunnerV2(V2Agent())
        .with_name("v2-agent")
        .with_grpc("0.0.0.0:50051")
    )
    asyncio.run(runner.run())
