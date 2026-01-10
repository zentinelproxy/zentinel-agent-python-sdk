"""Wire protocol integration tests.

These tests verify that the SDK correctly handles the wire protocol
by mocking the proxy side and testing full message round-trips.

This allows testing protocol compatibility without requiring Sentinel.
"""

import asyncio
import json
import struct
import tempfile
from pathlib import Path

import pytest

from sentinel_agent_sdk import Agent, Decision, Request, Response
from sentinel_agent_sdk.protocol import PROTOCOL_VERSION, EventType
from sentinel_agent_sdk.runner import AgentHandler


class SimpleTestAgent(Agent):
    """Simple agent for testing."""

    @property
    def name(self) -> str:
        return "test-agent"

    async def on_request(self, request: Request) -> Decision:
        if request.path_starts_with("/block"):
            return Decision.deny().with_body("Blocked").with_tag("blocked")
        return (
            Decision.allow()
            .add_response_header("X-Test", "value")
            .with_tag("allowed")
        )


def encode_message(data: dict) -> bytes:
    """Encode message with length prefix (proxy side encoding)."""
    json_bytes = json.dumps(data).encode("utf-8")
    return struct.pack(">I", len(json_bytes)) + json_bytes


def decode_message(data: bytes) -> dict:
    """Decode length-prefixed message (proxy side decoding)."""
    length = struct.unpack(">I", data[:4])[0]
    return json.loads(data[4 : 4 + length].decode("utf-8"))


class TestWireProtocolRoundTrip:
    """Test full wire protocol round-trips."""

    @pytest.fixture
    def handler(self) -> AgentHandler:
        """Create agent handler for testing."""
        return AgentHandler(SimpleTestAgent())

    @pytest.mark.asyncio
    async def test_request_headers_event_roundtrip(self, handler: AgentHandler) -> None:
        """Test request headers event handling."""
        # Simulate what Sentinel sends
        request_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "request_headers",
            "payload": {
                "metadata": {
                    "correlation_id": "test-corr-123",
                    "request_id": "req-456",
                    "client_ip": "192.168.1.100",
                    "client_port": 54321,
                    "server_name": "api.example.com",
                    "protocol": "HTTP/1.1",
                    "timestamp": "2024-01-15T10:30:00Z",
                },
                "method": "GET",
                "uri": "/allowed/path?foo=bar",
                "headers": {
                    "host": ["api.example.com"],
                    "user-agent": ["test-client/1.0"],
                    "accept": ["application/json"],
                },
            },
        }

        # Handle the event
        response = await handler.handle_event(request_event)

        # Verify response format
        assert response["version"] == PROTOCOL_VERSION
        assert response["decision"] == "allow"
        assert any(
            h.get("set", {}).get("name") == "X-Test"
            for h in response["request_headers"] + response["response_headers"]
        )
        assert "allowed" in response["audit"]["tags"]

    @pytest.mark.asyncio
    async def test_block_decision_roundtrip(self, handler: AgentHandler) -> None:
        """Test block decision wire format."""
        request_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "request_headers",
            "payload": {
                "metadata": {
                    "correlation_id": "test-block-123",
                    "request_id": "req-789",
                    "client_ip": "10.0.0.1",
                    "client_port": 12345,
                    "protocol": "HTTP/1.1",
                    "timestamp": "2024-01-15T10:30:00Z",
                },
                "method": "GET",
                "uri": "/block/this",
                "headers": {},
            },
        }

        response = await handler.handle_event(request_event)

        # Verify block response format
        assert response["version"] == PROTOCOL_VERSION
        assert isinstance(response["decision"], dict)
        assert "block" in response["decision"]
        assert response["decision"]["block"]["status"] == 403
        assert response["decision"]["block"]["body"] == "Blocked"
        assert "blocked" in response["audit"]["tags"]

    @pytest.mark.asyncio
    async def test_configure_event(self, handler: AgentHandler) -> None:
        """Test configure event handling."""
        config_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "configure",
            "payload": {
                "agent_id": "test-agent",
                "config": {"key": "value"},
            },
        }

        response = await handler.handle_event(config_event)
        assert response.get("success") is True

    @pytest.mark.asyncio
    async def test_response_headers_event(self, handler: AgentHandler) -> None:
        """Test response headers event handling."""
        # First, send request headers to cache the request
        request_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "request_headers",
            "payload": {
                "metadata": {
                    "correlation_id": "test-resp-123",
                    "request_id": "req-101",
                    "client_ip": "127.0.0.1",
                    "client_port": 11111,
                    "protocol": "HTTP/1.1",
                    "timestamp": "2024-01-15T10:30:00Z",
                },
                "method": "GET",
                "uri": "/test",
                "headers": {},
            },
        }
        await handler.handle_event(request_event)

        # Now send response headers
        response_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "response_headers",
            "payload": {
                "correlation_id": "test-resp-123",
                "status": 200,
                "headers": {
                    "content-type": ["application/json"],
                },
            },
        }

        response = await handler.handle_event(response_event)

        assert response["version"] == PROTOCOL_VERSION
        assert response["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_request_complete_event(self, handler: AgentHandler) -> None:
        """Test request complete event handling."""
        # First, cache a request
        request_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "request_headers",
            "payload": {
                "metadata": {
                    "correlation_id": "test-complete-123",
                    "request_id": "req-202",
                    "client_ip": "127.0.0.1",
                    "client_port": 22222,
                    "protocol": "HTTP/1.1",
                    "timestamp": "2024-01-15T10:30:00Z",
                },
                "method": "GET",
                "uri": "/test",
                "headers": {},
            },
        }
        await handler.handle_event(request_event)

        # Send request complete
        complete_event = {
            "version": PROTOCOL_VERSION,
            "event_type": "request_complete",
            "payload": {
                "correlation_id": "test-complete-123",
                "status": 200,
                "duration_ms": 50,
                "request_body_size": 0,
                "response_body_size": 1024,
                "upstream_attempts": 1,
            },
        }

        response = await handler.handle_event(complete_event)
        assert response.get("success") is True


class TestSocketCommunication:
    """Test actual Unix socket communication."""

    @pytest.mark.asyncio
    async def test_socket_roundtrip(self) -> None:
        """Test full socket communication round-trip."""
        from sentinel_agent_sdk.runner import AgentRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            agent = SimpleTestAgent()
            runner = AgentRunner(agent).with_socket(socket_path)

            # Start server in background
            server_task = asyncio.create_task(runner.run())

            # Wait for socket to be created
            for _ in range(20):
                if socket_path.exists():
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("Socket was not created")

            try:
                # Connect as client (simulating proxy)
                reader, writer = await asyncio.open_unix_connection(str(socket_path))

                # Send request headers event
                request = {
                    "version": PROTOCOL_VERSION,
                    "event_type": "request_headers",
                    "payload": {
                        "metadata": {
                            "correlation_id": "socket-test-123",
                            "request_id": "req-sock",
                            "client_ip": "127.0.0.1",
                            "client_port": 33333,
                            "protocol": "HTTP/1.1",
                            "timestamp": "2024-01-15T10:30:00Z",
                        },
                        "method": "GET",
                        "uri": "/allowed",
                        "headers": {},
                    },
                }

                # Encode and send
                encoded = encode_message(request)
                writer.write(encoded)
                await writer.drain()

                # Read response
                length_bytes = await reader.read(4)
                length = struct.unpack(">I", length_bytes)[0]
                response_bytes = await reader.read(length)
                response = json.loads(response_bytes.decode("utf-8"))

                # Verify response
                assert response["version"] == PROTOCOL_VERSION
                assert response["decision"] == "allow"
                assert "allowed" in response["audit"]["tags"]

                writer.close()
                await writer.wait_closed()

            finally:
                # Shutdown server
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    pass


class TestMessageEncoding:
    """Test message encoding/decoding matches protocol spec."""

    def test_length_prefix_encoding(self) -> None:
        """Verify 4-byte big-endian length prefix."""
        data = {"test": "value"}
        encoded = encode_message(data)

        # First 4 bytes are length
        length = struct.unpack(">I", encoded[:4])[0]
        json_part = encoded[4:]

        assert length == len(json_part)
        assert json.loads(json_part.decode()) == data

    def test_max_message_size_check(self) -> None:
        """Verify max message size is enforced."""
        from sentinel_agent_sdk.protocol import MAX_MESSAGE_SIZE

        # Create message that would exceed limit
        large_data = {"data": "x" * (MAX_MESSAGE_SIZE + 1)}

        from sentinel_agent_sdk.protocol import encode_message as sdk_encode

        with pytest.raises(ValueError, match="exceeds maximum"):
            sdk_encode(large_data)

    def test_header_ops_format(self) -> None:
        """Verify header operations match Rust serde format."""
        response = (
            Decision.allow()
            .add_request_header("X-Add", "value")
            .remove_request_header("X-Remove")
            .build()
        )

        data = response.to_dict()

        # Find the set operation
        set_op = next(
            (h for h in data["request_headers"] if "set" in h), None
        )
        assert set_op == {"set": {"name": "X-Add", "value": "value"}}

        # Find the remove operation
        remove_op = next(
            (h for h in data["request_headers"] if "remove" in h), None
        )
        assert remove_op == {"remove": {"name": "X-Remove"}}
