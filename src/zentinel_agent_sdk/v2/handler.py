"""V2 handler adapter that bridges AgentV2 to the protocol layer."""

from __future__ import annotations

import logging
from typing import Any

from zentinel_agent_sdk.decision import Decision
from zentinel_agent_sdk.protocol import (
    ConfigureEvent,
    EventType,
    GuardrailInspectEvent,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
)
from zentinel_agent_sdk.request import Request
from zentinel_agent_sdk.response import Response
from zentinel_agent_sdk.v2.agent import AgentV2
from zentinel_agent_sdk.v2.types import (
    AgentCapabilities,
    DrainReason,
    HandshakeRequest,
    HandshakeResponse,
    HealthStatus,
    MetricsReport,
    ShutdownReason,
)

logger = logging.getLogger("zentinel_agent_sdk.v2")


class AgentHandlerV2:
    """Handler that wraps an AgentV2 and provides protocol v2 handling.

    This adapter:
    - Handles v2 handshake with capability negotiation
    - Routes protocol events to agent methods
    - Manages request caching for correlation
    - Provides health and metrics endpoints
    """

    def __init__(self, agent: AgentV2) -> None:
        """Initialize the handler.

        Args:
            agent: The AgentV2 instance to wrap.
        """
        self._agent = agent
        self._requests: dict[str, Request] = {}
        self._request_bodies: dict[str, bytes] = {}
        self._response_bodies: dict[str, bytes] = {}

    @property
    def agent(self) -> AgentV2:
        """Get the underlying agent."""
        return self._agent

    def capabilities(self) -> AgentCapabilities:
        """Get agent capabilities."""
        return self._agent.capabilities()

    async def on_handshake(self, request: HandshakeRequest) -> HandshakeResponse:
        """Handle v2 handshake from proxy.

        Args:
            request: The handshake request.

        Returns:
            Handshake response with capabilities.
        """
        # Process configuration if present
        if request.config:
            try:
                await self._agent.on_configure(request.config)
            except Exception as e:
                return HandshakeResponse.failure(f"Configuration rejected: {e}")

        return HandshakeResponse.success_response(self.capabilities())

    def health_status(self) -> HealthStatus:
        """Get current health status."""
        return self._agent.health_status()

    def metrics_report(self) -> MetricsReport | None:
        """Get current metrics report."""
        return self._agent.metrics_report()

    async def on_configure(self, config: dict[str, Any], version: str | None = None) -> bool:
        """Handle configuration update.

        Args:
            config: Configuration dictionary.
            version: Optional config version string.

        Returns:
            True if configuration was accepted.
        """
        try:
            await self._agent.on_configure(config)
            return True
        except Exception as e:
            logger.error(f"Configuration failed: {e}")
            return False

    async def on_shutdown(self, reason: ShutdownReason, grace_period_ms: int) -> None:
        """Handle shutdown request."""
        self._agent.on_shutdown(reason, grace_period_ms)

    async def on_drain(self, duration_ms: int, reason: DrainReason) -> None:
        """Handle drain request."""
        self._agent.on_drain(duration_ms, reason)

    async def on_stream_closed(self) -> None:
        """Handle stream closure."""
        self._agent.on_stream_closed()

    async def handle_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Handle an incoming protocol event.

        Args:
            event: The protocol event dictionary.

        Returns:
            The response dictionary to send back.
        """
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        try:
            if event_type == EventType.CONFIGURE.value:
                return await self._handle_configure(payload)
            elif event_type == EventType.REQUEST_HEADERS.value:
                return await self._handle_request_headers(payload)
            elif event_type == EventType.REQUEST_BODY_CHUNK.value:
                return await self._handle_request_body_chunk(payload)
            elif event_type == EventType.RESPONSE_HEADERS.value:
                return await self._handle_response_headers(payload)
            elif event_type == EventType.RESPONSE_BODY_CHUNK.value:
                return await self._handle_response_body_chunk(payload)
            elif event_type == EventType.REQUEST_COMPLETE.value:
                return await self._handle_request_complete(payload)
            elif event_type == EventType.GUARDRAIL_INSPECT.value:
                return await self._handle_guardrail_inspect(payload)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                return Decision.allow().build().to_dict()
        except Exception as e:
            logger.exception(f"Error handling event {event_type}: {e}")
            return Decision.allow().build().to_dict()

    async def _handle_configure(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle configuration event."""
        event = ConfigureEvent.from_dict(payload)
        try:
            await self._agent.on_configure(event.config)
            logger.info(f"Agent configured: {event.agent_id}")
            return {"success": True}
        except Exception as e:
            logger.error(f"Configuration failed: {e}")
            return {"success": False, "error": str(e)}

    async def _handle_request_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle request headers event."""
        event = RequestHeadersEvent.from_dict(payload)
        request = Request(event)

        # Cache request for response correlation
        self._requests[event.metadata.correlation_id] = request
        self._request_bodies[event.metadata.correlation_id] = b""

        decision = await self._agent.on_request(request)
        return decision.build().to_dict()

    async def _handle_request_body_chunk(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle request body chunk event."""
        event = RequestBodyChunkEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Accumulate body chunks
        if correlation_id in self._request_bodies:
            self._request_bodies[correlation_id] += event.data

        # Only call handler on last chunk
        if event.is_last and correlation_id in self._requests:
            request = self._requests[correlation_id].with_body(
                self._request_bodies.get(correlation_id, b"")
            )
            decision = await self._agent.on_request_body(request)
            return decision.build().to_dict()

        # For non-final chunks, return allow with needs_more
        return Decision.allow().needs_more_data().build().to_dict()

    async def _handle_response_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle response headers event."""
        event = ResponseHeadersEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Get cached request
        request = self._requests.get(correlation_id)
        if request is None:
            logger.warning(f"No cached request for correlation_id: {correlation_id}")
            return Decision.allow().build().to_dict()

        response = Response(event)
        self._response_bodies[correlation_id] = b""

        decision = await self._agent.on_response(request, response)
        return decision.build().to_dict()

    async def _handle_response_body_chunk(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle response body chunk event."""
        event = ResponseBodyChunkEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Accumulate body chunks
        if correlation_id in self._response_bodies:
            self._response_bodies[correlation_id] += event.data

        # Only call handler on last chunk
        if event.is_last and correlation_id in self._requests:
            request = self._requests[correlation_id]
            # Create response with body
            response_event = ResponseHeadersEvent(
                correlation_id=correlation_id,
                status=200,  # We don't have status here, use default
                headers={},
            )
            response = Response(response_event).with_body(
                self._response_bodies.get(correlation_id, b"")
            )
            decision = await self._agent.on_response_body(request, response)
            return decision.build().to_dict()

        return Decision.allow().needs_more_data().build().to_dict()

    async def _handle_request_complete(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle request complete event."""
        event = RequestCompleteEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Get and cleanup cached request
        request = self._requests.pop(correlation_id, None)
        self._request_bodies.pop(correlation_id, None)
        self._response_bodies.pop(correlation_id, None)

        if request is not None:
            await self._agent.on_request_complete(
                request, event.status, event.duration_ms
            )

        return {"success": True}

    async def _handle_guardrail_inspect(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle guardrail inspection event."""
        event = GuardrailInspectEvent.from_dict(payload)
        response = await self._agent.on_guardrail_inspect(event)
        return response.to_dict()
