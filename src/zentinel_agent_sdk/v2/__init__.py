"""Zentinel Agent SDK v2 Protocol support.

This module provides v2 protocol support including:
- AgentV2 base class with capability reporting
- gRPC and UDS transport options
- Health reporting
- Flow control awareness
- Streaming body support

Example:
    from zentinel_agent_sdk import Decision, Request
    from zentinel_agent_sdk.v2 import AgentV2, AgentCapabilities, AgentRunnerV2

    class MyAgent(AgentV2):
        @property
        def name(self) -> str:
            return "my-agent"

        def capabilities(self) -> AgentCapabilities:
            return (
                AgentCapabilities("my-agent", "My Agent", "1.0.0")
                .with_streaming_body(True)
                .with_flow_control(True)
            )

        async def on_request(self, request: Request) -> Decision:
            return Decision.allow()

    if __name__ == "__main__":
        import asyncio
        runner = (
            AgentRunnerV2(MyAgent())
            .with_name("my-agent")
            .with_grpc("0.0.0.0:50051")
        )
        asyncio.run(runner.run())
"""

from zentinel_agent_sdk.v2.agent import AgentV2
from zentinel_agent_sdk.v2.handler import AgentHandlerV2
from zentinel_agent_sdk.v2.runner import (
    AgentRunnerV2,
    TransportConfig,
    TransportType,
    V2RunnerConfig,
    parse_v2_args,
    run_agent_v2,
)
from zentinel_agent_sdk.v2.types import (
    PROTOCOL_VERSION_2,
    AgentCapabilities,
    AgentFeatures,
    AgentLimits,
    DrainReason,
    HandshakeRequest,
    HandshakeResponse,
    HealthConfig,
    HealthState,
    HealthStatus,
    MetricsReport,
    ShutdownReason,
)

__all__ = [
    # Agent
    "AgentV2",
    # Handler
    "AgentHandlerV2",
    # Runner
    "AgentRunnerV2",
    "TransportConfig",
    "TransportType",
    "V2RunnerConfig",
    "parse_v2_args",
    "run_agent_v2",
    # Types
    "PROTOCOL_VERSION_2",
    "AgentCapabilities",
    "AgentFeatures",
    "AgentLimits",
    "HealthConfig",
    "HealthState",
    "HealthStatus",
    "MetricsReport",
    "HandshakeRequest",
    "HandshakeResponse",
    "ShutdownReason",
    "DrainReason",
]
