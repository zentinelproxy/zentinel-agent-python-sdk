"""A v2 agent demonstrating dual transport (gRPC + UDS).

This agent runs both:
- gRPC server on TCP port for remote connections
- UDS server for local connections with v2 protocol
"""

import asyncio
import logging

from zentinel_agent_sdk import Decision, Request
from zentinel_agent_sdk.v2 import AgentCapabilities, AgentRunnerV2, AgentV2

logger = logging.getLogger(__name__)


class DualTransportAgent(AgentV2):
    """Agent supporting both gRPC and UDS transports."""

    @property
    def name(self) -> str:
        return "dual-transport-agent"

    def capabilities(self) -> AgentCapabilities:
        """Define agent capabilities."""
        return (
            AgentCapabilities("dual-transport-agent", "Dual Transport Agent", "1.0.0")
            .with_streaming_body(True)
            .with_flow_control(True)
            .with_concurrent_requests(50)
        )

    async def on_request(self, request: Request) -> Decision:
        """Process incoming requests."""
        logger.info(f"Processing request (dual transport): {request.method()} {request.path()}")

        return Decision.allow().add_request_header("X-Agent", "dual-transport")


if __name__ == "__main__":
    # Run with both gRPC and UDS transports
    runner = (
        AgentRunnerV2(DualTransportAgent())
        .with_name("dual-transport-agent")
        .with_both("0.0.0.0:50051", "/tmp/dual-transport-agent.sock")
    )
    asyncio.run(runner.run())
