"""V2 handler adapter that bridges an agent to the protocol layer.

The handler is transport neutral. Events arrive as dictionaries in the JSON
shape the proxy uses on the Unix socket (the serde form of the Rust protocol
types), and every handler returns an `AgentResponse` dictionary in that same
shape. The UDS server passes them through as they are; the gRPC server
converts protobuf messages to and from them.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from zentinel_agent_sdk.agent import Agent
from zentinel_agent_sdk.decision import Decision
from zentinel_agent_sdk.protocol import (
    EventType,
    GuardrailInspectEvent,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    RequestMetadata,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
)
from zentinel_agent_sdk.request import Request
from zentinel_agent_sdk.response import Response
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

#: Requests remembered between their header and body/response events. The
#: proxy sends `request_complete` only to agents that subscribe to it, so the
#: cache is bounded rather than relying on that event to empty it.
MAX_TRACKED_REQUESTS = 10_000


def _allow() -> dict[str, Any]:
    return Decision.allow().build().to_dict()


class AgentHandlerV2:
    """Routes protocol v2 events to an agent's methods.

    One handler serves every connection of a runner: the proxy keeps a pool
    of connections per agent and may send a request's headers on one and its
    body on another, so per-request state must not be per connection.
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the handler.

        Args:
            agent: The agent to wrap. An `AgentV2` reports its own
                capabilities; a plain `Agent` gets defaults from its name.
        """
        self._agent = agent
        self._requests: OrderedDict[str, Request] = OrderedDict()
        self._request_bodies: dict[str, bytes] = {}
        self._response_bodies: dict[str, bytes] = {}
        self._response_status: dict[str, int] = {}

    @property
    def agent(self) -> Agent:
        """Get the underlying agent."""
        return self._agent

    def capabilities(self) -> AgentCapabilities:
        """Get agent capabilities."""
        caps = getattr(self._agent, "capabilities", None)
        if callable(caps):
            result = caps()
            if isinstance(result, AgentCapabilities):
                return result
        name = self._agent.name
        return AgentCapabilities(name, name, "0.0.0")

    async def on_handshake(self, request: HandshakeRequest) -> HandshakeResponse:
        """Answer the handshake.

        The configuration is not applied here: the proxy follows the
        handshake with a Configure message on every connection, and that is
        what reaches `on_configure` (as in the Rust SDK).
        """
        if 2 not in request.supported_versions:
            return HandshakeResponse.failure(
                f"protocol v2 not offered (proxy supports {request.supported_versions})"
            )
        return HandshakeResponse.success_response(self.capabilities())

    def health_status(self) -> HealthStatus:
        """Get current health status."""
        fn = getattr(self._agent, "health_status", None)
        if callable(fn):
            status = fn()
            if isinstance(status, HealthStatus):
                return status
        return HealthStatus.healthy(self.capabilities().agent_id)

    def metrics_report(self) -> MetricsReport | None:
        """Get current metrics report."""
        fn = getattr(self._agent, "metrics_report", None)
        result = fn() if callable(fn) else None
        return result if isinstance(result, MetricsReport) else None

    async def on_configure(self, config: Any, version: str | None = None) -> bool:
        """Apply a configuration.

        Returns:
            True if the agent accepted it (`on_configure` did not raise).
        """
        try:
            await self._agent.on_configure(config if config is not None else {})
            logger.info("Configuration applied%s", f" (version {version})" if version else "")
            return True
        except Exception as e:
            logger.error(f"Configuration rejected: {e}")
            return False

    async def on_shutdown(self, reason: ShutdownReason, grace_period_ms: int) -> None:
        """Handle shutdown request."""
        fn = getattr(self._agent, "on_shutdown", None)
        if callable(fn):
            fn(reason, grace_period_ms)

    async def on_drain(self, duration_ms: int, reason: DrainReason) -> None:
        """Handle drain request."""
        fn = getattr(self._agent, "on_drain", None)
        if callable(fn):
            fn(duration_ms, reason)

    async def on_stream_closed(self) -> None:
        """Handle stream closure."""
        fn = getattr(self._agent, "on_stream_closed", None)
        if callable(fn):
            fn()

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle one event and return the `AgentResponse` dictionary.

        Args:
            event_type: An `EventType` value, e.g. "request_headers".
            payload: The event in the proxy's JSON shape.
        """
        try:
            if event_type == EventType.CONFIGURE.value:
                accepted = await self.on_configure(
                    payload.get("config"), payload.get("config_version")
                )
                if accepted:
                    return _allow()
                return Decision.block(500).with_body("Configuration rejected").build().to_dict()
            if event_type == EventType.REQUEST_HEADERS.value:
                return await self._handle_request_headers(payload)
            if event_type == EventType.REQUEST_BODY_CHUNK.value:
                return await self._handle_request_body_chunk(payload)
            if event_type == EventType.RESPONSE_HEADERS.value:
                return await self._handle_response_headers(payload)
            if event_type == EventType.RESPONSE_BODY_CHUNK.value:
                return await self._handle_response_body_chunk(payload)
            if event_type == EventType.REQUEST_COMPLETE.value:
                return await self._handle_request_complete(payload)
            if event_type == EventType.GUARDRAIL_INSPECT.value:
                return await self._handle_guardrail_inspect(payload)
            logger.warning(f"Unhandled event type: {event_type}")
            return _allow()
        except Exception as e:
            logger.exception(f"Error handling event {event_type}: {e}")
            return _allow()

    async def handle_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Handle `{"event_type": ..., "payload": {...}}`.

        Kept for callers of the 0.2 API; transports use `dispatch`.
        """
        return await self.dispatch(str(event.get("event_type", "")), event.get("payload") or {})

    # ------------------------------------------------------------------
    # Per-request state
    # ------------------------------------------------------------------

    def _remember(self, correlation_id: str, request: Request) -> None:
        self._requests[correlation_id] = request
        self._requests.move_to_end(correlation_id)
        while len(self._requests) > MAX_TRACKED_REQUESTS:
            old, _ = self._requests.popitem(last=False)
            self._forget(old)

    def _forget(self, correlation_id: str) -> None:
        self._requests.pop(correlation_id, None)
        self._request_bodies.pop(correlation_id, None)
        self._response_bodies.pop(correlation_id, None)
        self._response_status.pop(correlation_id, None)

    def _request_for(self, correlation_id: str) -> Request:
        request = self._requests.get(correlation_id)
        if request is not None:
            return request
        # The agent did not see this request's headers (it is not subscribed
        # to them, or they went to another process): give it what is known.
        event = RequestHeadersEvent(
            metadata=RequestMetadata(
                correlation_id=correlation_id, request_id="", client_ip="", client_port=0
            ),
            method="",
            uri="",
            headers={},
        )
        return Request(event)

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _handle_request_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = RequestHeadersEvent.from_dict(payload)
        request = Request(event)
        cid = event.metadata.correlation_id
        self._remember(cid, request)
        self._request_bodies[cid] = b""
        decision = await self._agent.on_request(request)
        return decision.build().to_dict()

    async def _handle_request_body_chunk(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = RequestBodyChunkEvent.from_dict(payload)
        cid = event.correlation_id
        body = self._request_bodies.get(cid, b"") + event.data
        self._request_bodies[cid] = body
        if not event.is_last:
            return Decision.allow().needs_more_data().build().to_dict()
        request = self._request_for(cid).with_body(body)
        self._remember(cid, request)
        decision = await self._agent.on_request_body(request)
        return decision.build().to_dict()

    async def _handle_response_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = ResponseHeadersEvent.from_dict(payload)
        cid = event.correlation_id
        self._response_bodies[cid] = b""
        self._response_status[cid] = event.status
        decision = await self._agent.on_response(self._request_for(cid), Response(event))
        return decision.build().to_dict()

    async def _handle_response_body_chunk(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = ResponseBodyChunkEvent.from_dict(payload)
        cid = event.correlation_id
        body = self._response_bodies.get(cid, b"") + event.data
        self._response_bodies[cid] = body
        if not event.is_last:
            return Decision.allow().needs_more_data().build().to_dict()
        response_event = ResponseHeadersEvent(
            correlation_id=cid,
            status=self._response_status.get(cid, 200),
            headers={},
        )
        response = Response(response_event).with_body(body)
        decision = await self._agent.on_response_body(self._request_for(cid), response)
        return decision.build().to_dict()

    async def _handle_request_complete(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = RequestCompleteEvent.from_dict(payload)
        request = self._requests.get(event.correlation_id)
        self._forget(event.correlation_id)
        if request is not None:
            await self._agent.on_request_complete(request, event.status, event.duration_ms)
        return _allow()

    async def _handle_guardrail_inspect(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = GuardrailInspectEvent.from_dict(payload)
        result = await self._agent.on_guardrail_inspect(event)
        response = _allow()
        response["audit"] = {"custom": {"guardrail": result.to_dict()}}
        return response


def correlation_id_of(payload: dict[str, Any]) -> str:
    """The correlation id of an event payload (top level, or in `metadata`)."""
    cid = payload.get("correlation_id")
    if isinstance(cid, str) and cid:
        return cid
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        nested = metadata.get("correlation_id")
        if isinstance(nested, str):
            return nested
    return ""
