"""Agent protocol v2 on the wire, against the SDK's own servers.

These drive the UDS and gRPC servers the way the proxy does (see
`zentinel_agent_protocol::v2::uds` and `v2::client` in zentinelproxy/zentinel):
the handshake schema, the Configure message and its acknowledgement, ping,
and correlation ids on responses. The end-to-end check against a real proxy
is `tests/integration/test_conformance.py`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import grpc
import pytest

from zentinel_agent_sdk import Decision, Request
from zentinel_agent_sdk.v2 import AgentCapabilities, AgentRunnerV2, AgentV2
from zentinel_agent_sdk.v2.grpc_server import AgentServiceV2
from zentinel_agent_sdk.v2.handler import AgentHandlerV2
from zentinel_agent_sdk.v2.proto import agent_v2_pb2 as pb
from zentinel_agent_sdk.v2.proto import agent_v2_pb2_grpc as pb_grpc
from zentinel_agent_sdk.v2.uds import MessageType, encode_frame


class EchoConfigAgent(AgentV2):
    def __init__(self) -> None:
        self.config: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "wire-test"

    def capabilities(self) -> AgentCapabilities:
        return AgentCapabilities("wire-test", "Wire test", "1.0.0")

    async def on_configure(self, config: dict[str, Any]) -> None:
        if config.get("reject"):
            raise ValueError("rejected")
        self.config = config

    async def on_request(self, request: Request) -> Decision:
        value = str((self.config or {}).get("greeting", "unconfigured"))
        return Decision.allow().add_request_header("X-Config", value)

    async def on_request_body(self, request: Request) -> Decision:
        if b"evil" in request.body:
            return Decision.block(403).with_body("body:" + request.body_str)
        return Decision.allow()


def test_frame_length_counts_the_type_byte() -> None:
    frame = encode_frame(MessageType.PING, b"abc")
    assert frame == struct.pack(">I", 4) + bytes([0x41]) + b"abc"


async def _read(reader: asyncio.StreamReader) -> tuple[int, Any]:
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    body = await reader.readexactly(length)
    return body[0], json.loads(body[1:]) if len(body) > 1 else None


async def _send(writer: asyncio.StreamWriter, msg_type: int, value: Any) -> None:
    writer.write(encode_frame(msg_type, json.dumps(value).encode()))
    await writer.drain()


@pytest.fixture
def socket_path() -> Any:
    # Short path: Unix socket paths are limited to ~104 bytes.
    with tempfile.TemporaryDirectory(prefix="zs-") as d:
        yield Path(d) / "a.sock"


async def _serve_uds(socket_path: Path) -> tuple[AgentRunnerV2, asyncio.Task[None]]:
    runner = AgentRunnerV2(EchoConfigAgent()).with_uds(socket_path)
    task = asyncio.create_task(runner._run_uds_server())
    for _ in range(100):
        if socket_path.exists():
            break
        await asyncio.sleep(0.01)
    return runner, task


async def test_uds_handshake_configure_and_events(socket_path: Path) -> None:
    runner, task = await _serve_uds(socket_path)
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        await _send(
            writer,
            MessageType.HANDSHAKE_REQUEST,
            {
                "supported_versions": [2],
                "proxy_id": "zentinel-proxy",
                "proxy_version": "test",
                "config": {"greeting": "hi"},
                "supported_encodings": ["json"],
            },
        )
        msg_type, hs = await _read(reader)
        assert msg_type == MessageType.HANDSHAKE_RESPONSE
        # Every field the proxy's UdsHandshakeResponse requires, non-null.
        assert hs["protocol_version"] == 2 and hs["success"] is True
        assert hs["encoding"] == "json"
        caps = hs["capabilities"]
        for key in ("agent_id", "name", "version", "supported_events", "features", "limits"):
            assert caps[key] is not None, key
        assert set(caps["features"]) == {
            "streaming_body",
            "websocket",
            "guardrails",
            "config_push",
            "metrics_export",
            "concurrent_requests",
            "cancellation",
            "flow_control",
            "health_reporting",
        }
        assert set(caps["limits"]) == {"max_body_size", "max_concurrency", "preferred_chunk_size"}

        await _send(
            writer,
            MessageType.CONFIGURE,
            {
                "config": {"greeting": "configured"},
                "config_version": None,
                "correlation_id": "cfg-1",
            },
        )
        msg_type, resp = await _read(reader)
        assert msg_type == MessageType.AGENT_RESPONSE
        assert resp["decision"] == "allow" and resp["version"] == 2
        assert resp["audit"]["custom"]["correlation_id"] == "cfg-1"

        await _send(writer, MessageType.PING, {"sequence": 7})
        msg_type, pong = await _read(reader)
        assert msg_type == MessageType.PONG and pong == {"sequence": 7}

        await _send(
            writer,
            MessageType.REQUEST_HEADERS,
            {
                "metadata": {
                    "correlation_id": "req-1",
                    "request_id": "r",
                    "client_ip": "127.0.0.1",
                    "client_port": 1,
                    "protocol": "HTTP/1.1",
                    "timestamp": "now",
                },
                "method": "POST",
                "uri": "/x",
                "headers": {"host": ["example"]},
            },
        )
        _, resp = await _read(reader)
        assert resp["audit"]["custom"]["correlation_id"] == "req-1"
        assert resp["request_headers"] == [{"set": {"name": "X-Config", "value": "configured"}}]

        await _send(
            writer,
            MessageType.REQUEST_BODY_CHUNK,
            {
                "correlation_id": "req-1",
                "data": base64.b64encode(b"so evil").decode(),
                "is_last": True,
                "chunk_index": 0,
                "bytes_received": 7,
            },
        )
        _, resp = await _read(reader)
        assert resp["decision"] == {"block": {"status": 403, "body": "body:so evil"}}
        assert resp["audit"]["custom"]["correlation_id"] == "req-1"
    finally:
        writer.close()
        runner._shutdown_event.set()
        await task


async def test_uds_rejected_configuration_is_a_block(socket_path: Path) -> None:
    runner, task = await _serve_uds(socket_path)
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        await _send(
            writer,
            MessageType.HANDSHAKE_REQUEST,
            {"supported_versions": [2], "proxy_id": "p", "proxy_version": "t", "config": None},
        )
        await _read(reader)
        await _send(
            writer, MessageType.CONFIGURE, {"config": {"reject": True}, "correlation_id": "cfg-2"}
        )
        _, resp = await _read(reader)
        assert resp["decision"]["block"]["status"] == 500
        assert resp["audit"]["custom"]["correlation_id"] == "cfg-2"
    finally:
        writer.close()
        runner._shutdown_event.set()
        await task


async def _grpc_stream(messages: list[pb.ProxyToAgent], expect: int) -> list[pb.AgentToProxy]:
    server = grpc.aio.server()
    pb_grpc.add_AgentServiceV2Servicer_to_server(
        AgentServiceV2(AgentHandlerV2(EchoConfigAgent())), server
    )
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            stub = pb_grpc.AgentServiceV2Stub(channel)
            out: list[pb.AgentToProxy] = []
            call = stub.ProcessStream(iter(messages))
            async for msg in call:
                out.append(msg)
                if len(out) == expect:
                    break
            call.cancel()
            return out
    finally:
        await server.stop(None)


async def test_grpc_handshake_configure_ping_and_request() -> None:
    out = await _grpc_stream(
        [
            pb.ProxyToAgent(handshake=pb.HandshakeRequest(supported_versions=[2, 1], proxy_id="p")),
            pb.ProxyToAgent(
                configure=pb.ConfigureEvent(config_json='{"greeting":"grpc"}', is_initial=True)
            ),
            pb.ProxyToAgent(ping=pb.Ping(sequence=3, timestamp_ms=1)),
            pb.ProxyToAgent(
                request_headers=pb.RequestHeadersEvent(
                    metadata=pb.RequestMetadata(correlation_id="g-1"),
                    method="GET",
                    uri="/",
                    headers=[pb.Header(name="host", value="h")],
                )
            ),
        ],
        expect=3,
    )
    hs, pong, resp = out
    assert hs.handshake.success and hs.handshake.protocol_version == 2
    assert hs.handshake.capabilities.agent_id == "wire-test"
    # The Pong confirms the configure, so it must come after it was applied.
    assert pong.pong.sequence == 3
    assert resp.response.correlation_id == "g-1"
    assert resp.response.WhichOneof("decision") == "allow"
    assert resp.response.request_headers[0].set.name == "X-Config"
    assert resp.response.request_headers[0].set.value == "grpc"


async def test_grpc_rejected_configuration_ends_the_stream() -> None:
    out = await _grpc_stream(
        [
            pb.ProxyToAgent(handshake=pb.HandshakeRequest(supported_versions=[2])),
            pb.ProxyToAgent(configure=pb.ConfigureEvent(config_json='{"reject":true}')),
            pb.ProxyToAgent(ping=pb.Ping(sequence=1)),
        ],
        expect=5,
    )
    assert [m.WhichOneof("message") for m in out] == ["handshake"]
