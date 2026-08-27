"""AgentV2 class with v2 protocol capabilities."""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

from zentinel_agent_sdk.agent import Agent
from zentinel_agent_sdk.v2.types import (
    AgentCapabilities,
    DrainReason,
    HealthStatus,
    MetricsReport,
    ShutdownReason,
)

if TYPE_CHECKING:
    pass


class AgentV2(Agent):
    """Agent with v2 protocol capabilities.

    Extends the base Agent class with v2-specific features:
    - Capability negotiation
    - Health reporting
    - Flow control
    - Metrics export

    Example:
        class MyAgent(AgentV2):
            @property
            def name(self) -> str:
                return "my-agent"

            def capabilities(self) -> AgentCapabilities:
                return (
                    AgentCapabilities("my-agent", "My Agent", "1.0.0")
                    .with_streaming_body(True)
                    .with_flow_control(True)
                    .with_concurrent_requests(100)
                )

            async def on_request(self, request: Request) -> Decision:
                return Decision.allow()
    """

    @abstractmethod
    def capabilities(self) -> AgentCapabilities:
        """Return agent capabilities for v2 handshake.

        Capabilities inform the proxy about what features this agent supports
        and its resource limits.

        Returns:
            Agent capabilities configuration.
        """
        ...

    def health_status(self) -> HealthStatus:
        """Get current health status.

        Override this to report custom health metrics.
        Default returns a healthy status with the agent ID.

        Returns:
            Current health status.
        """
        return HealthStatus.healthy(self.capabilities().agent_id)

    def metrics_report(self) -> MetricsReport | None:
        """Get current metrics report.

        Override this to export custom metrics.
        Default returns None, meaning no metrics are exported.

        Returns:
            Metrics report or None if no metrics to export.
        """
        return None

    def on_shutdown(self, reason: ShutdownReason, grace_period_ms: int) -> None:
        """Handle shutdown request from proxy.

        Called when the proxy requests graceful shutdown. The agent should
        finish processing in-flight requests within the grace period.

        Override this to perform cleanup operations.

        Args:
            reason: The reason for shutdown.
            grace_period_ms: Time in milliseconds to complete in-flight work.
        """
        pass

    def on_drain(self, duration_ms: int, reason: DrainReason) -> None:
        """Handle drain request from proxy.

        Called when the proxy wants the agent to stop accepting new requests
        while finishing existing ones. Used during config reloads or maintenance.

        Override this to update internal state to reject new requests.

        Args:
            duration_ms: Expected duration of the drain period.
            reason: The reason for draining.
        """
        pass

    def on_stream_closed(self) -> None:
        """Called when the gRPC stream is closed.

        Override this to perform cleanup when the connection to the proxy
        is lost.
        """
        pass
