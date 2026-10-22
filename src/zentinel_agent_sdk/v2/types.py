"""Protocol v2 type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

PROTOCOL_VERSION_2 = 2


class ShutdownReason(str, Enum):
    """Reason for agent shutdown request."""

    PROXY_SHUTDOWN = "proxy_shutdown"
    CONFIG_RELOAD = "config_reload"
    ADMIN_REQUEST = "admin_request"
    HEALTH_CHECK_FAILED = "health_check_failed"


class DrainReason(str, Enum):
    """Reason for agent drain request."""

    CONFIG_RELOAD = "config_reload"
    ROLLING_UPDATE = "rolling_update"
    MAINTENANCE = "maintenance"
    LOAD_SHEDDING = "load_shedding"


class HealthState(str, Enum):
    """Health state of the agent."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class AgentFeatures:
    """Features supported by the agent."""

    streaming_body: bool = False
    websocket: bool = False
    guardrails: bool = False
    config_push: bool = False
    metrics_export: bool = False
    concurrent_requests: int = 10
    cancellation: bool = False
    flow_control: bool = False
    health_reporting: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "streaming_body": self.streaming_body,
            "websocket": self.websocket,
            "guardrails": self.guardrails,
            "config_push": self.config_push,
            "metrics_export": self.metrics_export,
            "concurrent_requests": self.concurrent_requests,
            "cancellation": self.cancellation,
            "flow_control": self.flow_control,
            "health_reporting": self.health_reporting,
        }


@dataclass
class AgentLimits:
    """Resource limits for the agent."""

    max_body_size: int = 10 * 1024 * 1024  # 10MB
    preferred_chunk_size: int = 64 * 1024  # 64KB
    max_processing_time_ms: int | None = None
    max_concurrency: int = 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "max_body_size": self.max_body_size,
            "max_concurrency": self.max_concurrency,
            "preferred_chunk_size": self.preferred_chunk_size,
        }
        if self.max_processing_time_ms is not None:
            result["max_processing_time_ms"] = self.max_processing_time_ms
        return result


@dataclass
class HealthConfig:
    """Health reporting configuration."""

    report_interval_ms: int = 30000
    timeout_ms: int = 5000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "report_interval_ms": self.report_interval_ms,
            "timeout_ms": self.timeout_ms,
        }


# Event type numbers as the UDS handshake reports them (`supported_events`).
UDS_EVENT_NUMBERS: dict[str, int] = {
    "configure": 0,
    "request_headers": 1,
    "request_body_chunk": 2,
    "response_headers": 3,
    "response_body_chunk": 4,
    "request_complete": 5,
    "websocket_frame": 6,
    "guardrail_inspect": 7,
}

# Event type numbers of the gRPC `EventType` enum.
GRPC_EVENT_NUMBERS: dict[str, int] = {
    "request_headers": 1,
    "request_body_chunk": 2,
    "response_headers": 3,
    "response_body_chunk": 4,
    "request_complete": 5,
    "websocket_frame": 6,
    "guardrail_inspect": 7,
    "configure": 8,
}


def _default_events() -> list[str]:
    return [
        "request_headers",
        "request_body_chunk",
        "response_headers",
        "response_body_chunk",
        "request_complete",
    ]


@dataclass
class AgentCapabilities:
    """Agent capabilities for v2 handshake."""

    agent_id: str
    name: str
    version: str
    features: AgentFeatures = field(default_factory=AgentFeatures)
    limits: AgentLimits = field(default_factory=AgentLimits)
    health: HealthConfig = field(default_factory=HealthConfig)
    supported_events: list[str] = field(default_factory=_default_events)

    def to_uds_dict(self) -> dict[str, Any]:
        """Serialize as the UDS handshake's `capabilities` (`UdsCapabilities`).

        Every field is required by the proxy.
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "supported_events": [
                UDS_EVENT_NUMBERS[e] for e in self.supported_events if e in UDS_EVENT_NUMBERS
            ],
            "features": self.features.to_dict(),
            "limits": {
                "max_body_size": self.limits.max_body_size,
                "max_concurrency": self.limits.max_concurrency,
                "preferred_chunk_size": self.limits.preferred_chunk_size,
            },
        }

    def with_events(self, *events: str) -> AgentCapabilities:
        """Set the events the agent handles (e.g. "request_headers")."""
        self.supported_events = list(events)
        return self

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "features": self.features.to_dict(),
            "limits": self.limits.to_dict(),
            "health": self.health.to_dict(),
        }

    def with_streaming_body(self, enabled: bool = True) -> AgentCapabilities:
        """Enable streaming body support."""
        self.features.streaming_body = enabled
        return self

    def with_websocket(self, enabled: bool = True) -> AgentCapabilities:
        """Enable WebSocket support."""
        self.features.websocket = enabled
        return self

    def with_guardrails(self, enabled: bool = True) -> AgentCapabilities:
        """Enable guardrails support."""
        self.features.guardrails = enabled
        return self

    def with_config_push(self, enabled: bool = True) -> AgentCapabilities:
        """Enable configuration push support."""
        self.features.config_push = enabled
        return self

    def with_metrics_export(self, enabled: bool = True) -> AgentCapabilities:
        """Enable metrics export."""
        self.features.metrics_export = enabled
        return self

    def with_concurrent_requests(self, max_requests: int) -> AgentCapabilities:
        """Set maximum concurrent requests."""
        self.features.concurrent_requests = max_requests
        return self

    def with_cancellation(self, enabled: bool = True) -> AgentCapabilities:
        """Enable request cancellation support."""
        self.features.cancellation = enabled
        return self

    def with_flow_control(self, enabled: bool = True) -> AgentCapabilities:
        """Enable flow control support."""
        self.features.flow_control = enabled
        return self

    def with_health_reporting(self, enabled: bool = True) -> AgentCapabilities:
        """Enable health reporting."""
        self.features.health_reporting = enabled
        return self

    def with_max_body_size(self, size: int) -> AgentCapabilities:
        """Set maximum body size in bytes."""
        self.limits.max_body_size = size
        return self

    def with_preferred_chunk_size(self, size: int) -> AgentCapabilities:
        """Set preferred chunk size for streaming."""
        self.limits.preferred_chunk_size = size
        return self

    def with_max_processing_time_ms(self, ms: int) -> AgentCapabilities:
        """Set maximum processing time per request."""
        self.limits.max_processing_time_ms = ms
        return self

    def with_health_interval_ms(self, ms: int) -> AgentCapabilities:
        """Set health report interval."""
        self.health.report_interval_ms = ms
        return self


@dataclass
class HealthStatus:
    """Health status report from the agent."""

    agent_id: str
    state: HealthState = HealthState.HEALTHY
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "agent_id": self.agent_id,
            "state": self.state.value,
        }
        if self.message:
            result["message"] = self.message
        if self.details:
            result["details"] = self.details
        return result

    def is_healthy(self) -> bool:
        """Check if the agent is healthy."""
        return self.state == HealthState.HEALTHY

    @classmethod
    def healthy(cls, agent_id: str) -> HealthStatus:
        """Create a healthy status."""
        return cls(agent_id=agent_id, state=HealthState.HEALTHY)

    @classmethod
    def degraded(cls, agent_id: str, message: str) -> HealthStatus:
        """Create a degraded status."""
        return cls(agent_id=agent_id, state=HealthState.DEGRADED, message=message)

    @classmethod
    def unhealthy(cls, agent_id: str, message: str) -> HealthStatus:
        """Create an unhealthy status."""
        return cls(agent_id=agent_id, state=HealthState.UNHEALTHY, message=message)


@dataclass
class MetricsReport:
    """Metrics report from the agent."""

    agent_id: str
    timestamp: str
    metrics: dict[str, float] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "metrics": self.metrics,
            "labels": self.labels,
        }


@dataclass
class HandshakeRequest:
    """Handshake request from proxy to agent."""

    supported_versions: list[int]
    proxy_id: str
    proxy_version: str
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HandshakeRequest:
        """Create from dictionary."""
        return cls(
            supported_versions=data.get("supported_versions", [2]),
            proxy_id=data.get("proxy_id", ""),
            proxy_version=data.get("proxy_version", ""),
            config=data.get("config") or {},
        )


@dataclass
class HandshakeResponse:
    """Handshake response from agent to proxy."""

    success: bool
    capabilities: AgentCapabilities | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize as the UDS handshake response (`UdsHandshakeResponse`).

        `capabilities` is required even when the handshake is refused, so a
        placeholder is sent then.
        """
        caps = self.capabilities or AgentCapabilities("unknown", "unknown", "0.0.0")
        return {
            "protocol_version": PROTOCOL_VERSION_2,
            "capabilities": caps.to_uds_dict(),
            "success": self.success,
            "error": self.error,
            "encoding": "json",
        }

    @classmethod
    def success_response(cls, capabilities: AgentCapabilities) -> HandshakeResponse:
        """Create a successful handshake response."""
        return cls(success=True, capabilities=capabilities)

    @classmethod
    def failure(cls, error: str) -> HandshakeResponse:
        """Create a failed handshake response."""
        return cls(success=False, error=error)
