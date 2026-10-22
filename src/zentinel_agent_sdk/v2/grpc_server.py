"""Agent protocol v2 over gRPC: the `zentinel.agent.v2.AgentServiceV2` service.

The proxy opens one bidirectional `ProcessStream` per connection, sends a
handshake, then (since zentinel#603) a `ConfigureEvent` followed by a `Ping`;
the `Pong` tells it the configuration was handled. Events follow. Messages are
converted to the JSON shapes `AgentHandlerV2` works with, so both transports
run the same agent code.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

import grpc

from zentinel_agent_sdk.v2.handler import AgentHandlerV2
from zentinel_agent_sdk.v2.proto import agent_v2_pb2 as pb
from zentinel_agent_sdk.v2.proto import agent_v2_pb2_grpc as pb_grpc
from zentinel_agent_sdk.v2.types import GRPC_EVENT_NUMBERS, PROTOCOL_VERSION_2

logger = logging.getLogger("zentinel_agent_sdk.v2")

_EVENT_KINDS = {
    "request_headers": "request_headers",
    "request_body_chunk": "request_body_chunk",
    "response_headers": "response_headers",
    "response_body_chunk": "response_body_chunk",
    "request_complete": "request_complete",
    "guardrail": "guardrail_inspect",
    "websocket_frame": "websocket_frame",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _headers_map(headers: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for h in headers:
        out.setdefault(h.name, []).append(h.value)
    return out


def _opt(msg: Any, field: str) -> Any:
    return getattr(msg, field) if msg.HasField(field) else None


def event_to_dict(kind: str, ev: Any) -> dict[str, Any]:
    """Convert a `ProxyToAgent` event to the handler's JSON shape."""
    if kind == "request_headers":
        md = ev.metadata
        return {
            "metadata": {
                "correlation_id": md.correlation_id,
                "request_id": md.request_id,
                "client_ip": md.client_ip,
                "client_port": md.client_port,
                "server_name": _opt(md, "server_name"),
                "protocol": md.protocol,
                "tls_version": _opt(md, "tls_version"),
                "route_id": _opt(md, "route_id"),
                "upstream_id": _opt(md, "upstream_id"),
                "timestamp": str(md.timestamp_ms),
                "traceparent": _opt(md, "traceparent"),
            },
            "method": ev.method,
            "uri": ev.uri,
            "headers": _headers_map(ev.headers),
        }
    if kind in ("request_body_chunk", "response_body_chunk"):
        out = {
            "correlation_id": ev.correlation_id,
            "data": base64.b64encode(ev.data).decode("ascii"),
            "is_last": ev.is_last,
            "total_size": _opt(ev, "total_size"),
            "chunk_index": ev.chunk_index,
        }
        key = "bytes_received" if kind == "request_body_chunk" else "bytes_sent"
        out[key] = ev.bytes_transferred
        return out
    if kind == "response_headers":
        return {
            "correlation_id": ev.correlation_id,
            "status": ev.status_code,
            "headers": _headers_map(ev.headers),
        }
    if kind == "request_complete":
        return {
            "correlation_id": ev.correlation_id,
            "status": ev.status_code,
            "duration_ms": ev.duration_ms,
            "request_body_size": ev.bytes_received,
            "response_body_size": ev.bytes_sent,
            "error": _opt(ev, "error"),
        }
    if kind == "guardrail":
        return {
            "correlation_id": ev.correlation_id,
            "content": ev.content,
            "model": _opt(ev, "model"),
            "inspection_type": "prompt_injection",
        }
    return {"correlation_id": getattr(ev, "correlation_id", "")}


def _header_op(op: dict[str, Any]) -> pb.HeaderOp | None:
    if "set" in op:
        return pb.HeaderOp(set=pb.Header(name=op["set"]["name"], value=op["set"].get("value", "")))
    if "add" in op:
        return pb.HeaderOp(add=pb.Header(name=op["add"]["name"], value=op["add"].get("value", "")))
    if "remove" in op:
        return pb.HeaderOp(remove=op["remove"]["name"])
    return None


def response_to_proto(correlation_id: str, resp: dict[str, Any]) -> pb.AgentResponse:
    """Convert an `AgentResponse` dictionary to the protobuf message."""
    out = pb.AgentResponse(correlation_id=correlation_id, needs_more=bool(resp.get("needs_more")))
    decision = resp.get("decision", "allow")
    if isinstance(decision, dict) and "block" in decision:
        b = decision["block"]
        block = pb.BlockDecision(status=int(b.get("status", 403)))
        if b.get("body") is not None:
            block.body = b["body"]
        for name, value in (b.get("headers") or {}).items():
            block.headers.append(pb.Header(name=name, value=value))
        out.block.CopyFrom(block)
    elif isinstance(decision, dict) and "redirect" in decision:
        r = decision["redirect"]
        out.redirect.CopyFrom(pb.RedirectDecision(url=r["url"], status=int(r.get("status", 302))))
    elif isinstance(decision, dict) and "challenge" in decision:
        c = decision["challenge"]
        out.challenge.CopyFrom(
            pb.ChallengeDecision(
                challenge_type=c.get("challenge_type", ""), params=c.get("params") or {}
            )
        )
    else:
        out.allow.CopyFrom(pb.AllowDecision())
    for key, target in (
        ("request_headers", out.request_headers),
        ("response_headers", out.response_headers),
    ):
        for op in resp.get(key) or []:
            converted = _header_op(op)
            if converted is not None:
                target.append(converted)
    audit = resp.get("audit") or {}
    if audit:
        a = pb.AuditMetadata(
            tags=audit.get("tags", []),
            rule_ids=audit.get("rule_ids", []),
            reason_codes=audit.get("reason_codes", []),
            custom={
                k: v if isinstance(v, str) else json.dumps(v)
                for k, v in (audit.get("custom") or {}).items()
            },
        )
        if audit.get("confidence") is not None:
            a.confidence = float(audit["confidence"])
        out.audit.CopyFrom(a)
    return out


class AgentServiceV2(pb_grpc.AgentServiceV2Servicer):  # type: ignore[misc]
    """`zentinel.agent.v2.AgentServiceV2`, backed by an `AgentHandlerV2`."""

    def __init__(self, handler: AgentHandlerV2) -> None:
        self._handler = handler

    def _handshake(self, req: Any) -> pb.AgentToProxy:
        caps = self._handler.capabilities()
        f = caps.features
        capabilities = pb.AgentCapabilities(
            protocol_version=PROTOCOL_VERSION_2,
            agent_id=caps.agent_id,
            name=caps.name,
            version=caps.version,
            supported_events=[
                GRPC_EVENT_NUMBERS[e] for e in caps.supported_events if e in GRPC_EVENT_NUMBERS
            ],
            features=pb.AgentFeatures(
                streaming_body=f.streaming_body,
                websocket=f.websocket,
                guardrails=f.guardrails,
                config_push=f.config_push,
                metrics_export=f.metrics_export,
                concurrent_requests=f.concurrent_requests,
                cancellation=f.cancellation,
                flow_control=f.flow_control,
                health_reporting=f.health_reporting,
            ),
            limits=pb.AgentLimits(
                max_body_size=caps.limits.max_body_size,
                max_concurrency=caps.limits.max_concurrency,
                preferred_chunk_size=caps.limits.preferred_chunk_size,
            ),
            health_config=pb.HealthConfig(report_interval_ms=caps.health.report_interval_ms),
        )
        ok = PROTOCOL_VERSION_2 in list(req.supported_versions)
        hs = pb.HandshakeResponse(
            protocol_version=PROTOCOL_VERSION_2, capabilities=capabilities, success=ok
        )
        if not ok:
            hs.error = f"protocol v2 not offered (proxy supports {list(req.supported_versions)})"
        return pb.AgentToProxy(handshake=hs)

    async def _configure(self, ev: Any) -> bool:
        try:
            config = json.loads(ev.config_json) if ev.config_json else {}
        except json.JSONDecodeError as e:
            logger.error(f"Configuration is not valid JSON: {e}")
            return False
        version = ev.config_version if ev.HasField("config_version") else None
        return await self._handler.on_configure(config, version)

    async def _event(self, kind: str, ev: Any) -> pb.AgentToProxy:
        payload = event_to_dict(kind, ev)
        resp = await self._handler.dispatch(_EVENT_KINDS[kind], payload)
        cid = payload.get("correlation_id") or payload.get("metadata", {}).get("correlation_id", "")
        return pb.AgentToProxy(response=response_to_proto(cid, resp))

    @staticmethod
    def _pong(ping: Any) -> pb.AgentToProxy:
        return pb.AgentToProxy(
            pong=pb.Pong(
                sequence=ping.sequence, ping_timestamp_ms=ping.timestamp_ms, timestamp_ms=_now_ms()
            )
        )

    async def ProcessStream(  # noqa: N802 - gRPC method name
        self, request_iterator: AsyncIterator[Any], context: Any
    ) -> AsyncIterator[pb.AgentToProxy]:
        # The proxy waits for the response headers before it sends the
        # handshake; grpc.aio would hold them back until the first message.
        await context.send_initial_metadata(())
        queue: asyncio.Queue[pb.AgentToProxy | None] = asyncio.Queue()

        async def read() -> None:
            tasks: set[asyncio.Task[None]] = set()

            async def run_event(kind: str, ev: Any) -> None:
                queue.put_nowait(await self._event(kind, ev))

            try:
                async for msg in request_iterator:
                    kind = msg.WhichOneof("message")
                    if kind == "handshake":
                        queue.put_nowait(self._handshake(msg.handshake))
                    elif kind == "configure":
                        # Handled in order: the Ping that follows must not be
                        # answered before the configuration is applied.
                        if not await self._configure(msg.configure):
                            logger.error("Configuration rejected; ending the stream")
                            return
                    elif kind == "ping":
                        queue.put_nowait(self._pong(msg.ping))
                    elif kind in _EVENT_KINDS:
                        task = asyncio.create_task(run_event(kind, getattr(msg, kind)))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
            finally:
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                queue.put_nowait(None)

        reader = asyncio.create_task(read())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            reader.cancel()
            await self._handler.on_stream_closed()

    async def ProcessEvent(self, request: Any, context: Any) -> pb.AgentToProxy:  # noqa: N802
        kind = request.WhichOneof("message")
        if kind == "handshake":
            return self._handshake(request.handshake)
        if kind == "ping":
            return self._pong(request.ping)
        if kind == "configure":
            await self._configure(request.configure)
            return pb.AgentToProxy()
        if kind in _EVENT_KINDS:
            return await self._event(kind, getattr(request, kind))
        return pb.AgentToProxy()

    async def ControlStream(  # noqa: N802
        self, request_iterator: AsyncIterator[Any], context: Any
    ) -> AsyncIterator[pb.ProxyControl]:
        async for _ in request_iterator:
            pass
        return
        yield  # pragma: no cover - makes this an async generator


async def serve_grpc(handler: AgentHandlerV2, address: str, shutdown: asyncio.Event) -> None:
    """Serve `AgentServiceV2` on `address` until `shutdown` is set."""
    server = grpc.aio.server()
    pb_grpc.add_AgentServiceV2Servicer_to_server(AgentServiceV2(handler), server)
    if server.add_insecure_port(address) == 0:
        raise OSError(f"could not bind gRPC address {address}")
    await server.start()
    logger.info(f"gRPC server listening on {address}")
    try:
        await shutdown.wait()
    finally:
        await server.stop(grace=5.0)
