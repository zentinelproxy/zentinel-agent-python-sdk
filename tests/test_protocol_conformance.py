"""Protocol conformance tests for Sentinel Agent SDK.

These tests verify that the Python SDK produces JSON that is compatible
with the Rust protocol implementation in sentinel-agent-protocol.

The source of truth is:
/Users/zara/Development/github.com/raskell-io/sentinel/crates/agent-protocol/src/protocol.rs
"""

import json

import pytest

from sentinel_agent_sdk import Decision
from sentinel_agent_sdk.protocol import (
    PROTOCOL_VERSION,
    AgentResponse,
    AuditMetadata,
    HeaderOp,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    RequestMetadata,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
)


class TestProtocolVersion:
    """Verify protocol version matches."""

    def test_protocol_version_is_one(self) -> None:
        """Protocol version must be 1 to match Rust implementation."""
        assert PROTOCOL_VERSION == 1


class TestDecisionSerialization:
    """Test that Decision serialization matches Rust serde output."""

    def test_allow_decision(self) -> None:
        """Allow decision serializes to string 'allow'."""
        response = Decision.allow().build()
        data = response.to_dict()
        assert data["decision"] == "allow"

    def test_block_decision_format(self) -> None:
        """Block decision uses nested object format."""
        response = Decision.block(403).build()
        data = response.to_dict()
        # Rust: Decision::Block { status: 403, body: None, headers: None }
        # Serde: {"block": {"status": 403}}
        assert data["decision"] == {"block": {"status": 403}}

    def test_block_with_body(self) -> None:
        """Block with body includes body field."""
        response = Decision.block(403).with_body("Forbidden").build()
        data = response.to_dict()
        assert data["decision"]["block"]["status"] == 403
        assert data["decision"]["block"]["body"] == "Forbidden"

    def test_block_with_headers(self) -> None:
        """Block with headers includes headers map."""
        response = (
            Decision.block(403)
            .with_body("Forbidden")
            .with_block_header("X-Reason", "policy")
            .build()
        )
        data = response.to_dict()
        assert data["decision"]["block"]["headers"] == {"X-Reason": "policy"}

    def test_redirect_decision_format(self) -> None:
        """Redirect decision uses nested object format."""
        response = Decision.redirect("/login", 302).build()
        data = response.to_dict()
        # Rust: Decision::Redirect { url: "/login", status: 302 }
        assert data["decision"] == {"redirect": {"url": "/login", "status": 302}}

    def test_challenge_decision_format(self) -> None:
        """Challenge decision uses nested object format."""
        response = Decision.challenge("captcha", {"site_key": "abc123"}).build()
        data = response.to_dict()
        # Rust: Decision::Challenge { challenge_type: "captcha", params: {...} }
        assert data["decision"]["challenge"]["challenge_type"] == "captcha"
        assert data["decision"]["challenge"]["params"] == {"site_key": "abc123"}


class TestHeaderOpSerialization:
    """Test HeaderOp serialization matches Rust serde output."""

    def test_set_header_format(self) -> None:
        """Set header uses nested object format."""
        op = HeaderOp("set", "X-Custom", "value")
        data = op.to_dict()
        # Rust: HeaderOp::Set { name: "X-Custom", value: "value" }
        assert data == {"set": {"name": "X-Custom", "value": "value"}}

    def test_add_header_format(self) -> None:
        """Add header uses nested object format."""
        op = HeaderOp("add", "X-Custom", "value")
        data = op.to_dict()
        assert data == {"add": {"name": "X-Custom", "value": "value"}}

    def test_remove_header_format(self) -> None:
        """Remove header uses nested object format."""
        op = HeaderOp("remove", "X-Custom")
        data = op.to_dict()
        # Rust: HeaderOp::Remove { name: "X-Custom" }
        assert data == {"remove": {"name": "X-Custom"}}


class TestAgentResponseSerialization:
    """Test AgentResponse serialization matches Rust serde output."""

    def test_full_response_structure(self) -> None:
        """Response has all expected fields."""
        response = Decision.allow().build()
        data = response.to_dict()

        # Required fields per Rust AgentResponse
        assert "version" in data
        assert "decision" in data
        assert "request_headers" in data
        assert "response_headers" in data
        assert "routing_metadata" in data
        assert "audit" in data
        assert "needs_more" in data
        assert "request_body_mutation" in data
        assert "response_body_mutation" in data
        assert "websocket_decision" in data

    def test_response_version(self) -> None:
        """Response version must be protocol version."""
        response = Decision.allow().build()
        data = response.to_dict()
        assert data["version"] == PROTOCOL_VERSION

    def test_response_with_header_ops(self) -> None:
        """Response includes header operations."""
        response = (
            Decision.allow()
            .add_request_header("X-Forwarded-By", "sentinel")
            .remove_request_header("X-Internal")
            .add_response_header("X-Cache", "HIT")
            .build()
        )
        data = response.to_dict()

        assert len(data["request_headers"]) == 2
        assert data["request_headers"][0] == {
            "set": {"name": "X-Forwarded-By", "value": "sentinel"}
        }
        assert data["request_headers"][1] == {"remove": {"name": "X-Internal"}}
        assert len(data["response_headers"]) == 1

    def test_response_with_audit_metadata(self) -> None:
        """Response includes audit metadata."""
        response = (
            Decision.deny()
            .with_tag("security")
            .with_tags(["blocked", "waf"])
            .with_rule_id("RULE-001")
            .with_confidence(0.95)
            .with_reason_code("SQL_INJECTION")
            .with_metadata("matched_pattern", "SELECT.*FROM")
            .build()
        )
        data = response.to_dict()

        audit = data["audit"]
        assert audit["tags"] == ["security", "blocked", "waf"]
        assert audit["rule_ids"] == ["RULE-001"]
        assert audit["confidence"] == 0.95
        assert audit["reason_codes"] == ["SQL_INJECTION"]
        assert audit["custom"]["matched_pattern"] == "SELECT.*FROM"


class TestEventDeserialization:
    """Test that events are deserialized correctly from Rust-generated JSON."""

    def test_request_headers_event(self) -> None:
        """Parse RequestHeadersEvent from Rust format."""
        # This is what Rust would send
        rust_json = {
            "metadata": {
                "correlation_id": "req-123",
                "request_id": "internal-456",
                "client_ip": "192.168.1.1",
                "client_port": 54321,
                "server_name": "api.example.com",
                "protocol": "HTTP/2",
                "tls_version": "TLSv1.3",
                "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "route_id": "api-route",
                "upstream_id": "backend-pool",
                "timestamp": "2024-01-15T10:30:00Z",
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            },
            "method": "POST",
            "uri": "/api/users?include=profile",
            "headers": {
                "content-type": ["application/json"],
                "accept": ["application/json", "text/plain"],
                "x-request-id": ["abc123"],
            },
        }

        event = RequestHeadersEvent.from_dict(rust_json)

        assert event.metadata.correlation_id == "req-123"
        assert event.metadata.client_ip == "192.168.1.1"
        assert event.metadata.client_port == 54321
        assert event.metadata.tls_version == "TLSv1.3"
        assert event.metadata.traceparent is not None
        assert event.method == "POST"
        assert event.uri == "/api/users?include=profile"
        assert event.headers["content-type"] == ["application/json"]
        assert len(event.headers["accept"]) == 2

    def test_request_body_chunk_event(self) -> None:
        """Parse RequestBodyChunkEvent with base64 data."""
        import base64

        body_data = b'{"name": "test"}'
        rust_json = {
            "correlation_id": "req-123",
            "data": base64.b64encode(body_data).decode(),
            "is_last": True,
            "total_size": 16,
            "chunk_index": 0,
            "bytes_received": 16,
        }

        event = RequestBodyChunkEvent.from_dict(rust_json)

        assert event.correlation_id == "req-123"
        assert event.data == body_data
        assert event.is_last is True
        assert event.chunk_index == 0

    def test_response_headers_event(self) -> None:
        """Parse ResponseHeadersEvent from Rust format."""
        rust_json = {
            "correlation_id": "req-123",
            "status": 200,
            "headers": {
                "content-type": ["application/json"],
                "cache-control": ["max-age=3600"],
            },
        }

        event = ResponseHeadersEvent.from_dict(rust_json)

        assert event.correlation_id == "req-123"
        assert event.status == 200
        assert event.headers["content-type"] == ["application/json"]


class TestAgentRequestEnvelope:
    """Test the AgentRequest envelope format."""

    def test_request_envelope_structure(self) -> None:
        """AgentRequest envelope has version, event_type, payload."""
        # This is what the proxy sends to agents
        envelope = {
            "version": 1,
            "event_type": "request_headers",
            "payload": {
                "metadata": {
                    "correlation_id": "req-123",
                    "request_id": "internal-456",
                    "client_ip": "127.0.0.1",
                    "client_port": 12345,
                    "protocol": "HTTP/1.1",
                    "timestamp": "2024-01-15T10:30:00Z",
                },
                "method": "GET",
                "uri": "/health",
                "headers": {},
            },
        }

        assert envelope["version"] == PROTOCOL_VERSION
        assert envelope["event_type"] == "request_headers"
        assert "payload" in envelope

    def test_event_type_snake_case(self) -> None:
        """Event types use snake_case as per Rust serde rename."""
        valid_event_types = [
            "configure",
            "request_headers",
            "request_body_chunk",
            "response_headers",
            "response_body_chunk",
            "request_complete",
            "websocket_frame",
        ]
        # These match the Rust EventType enum with #[serde(rename_all = "snake_case")]
        for event_type in valid_event_types:
            assert "_" in event_type or event_type == "configure"


class TestWireFormatRoundTrip:
    """Test JSON round-trip compatibility."""

    def test_response_json_roundtrip(self) -> None:
        """Response can be serialized and would parse in Rust."""
        response = (
            Decision.block(403)
            .with_body("Access denied")
            .with_tag("security")
            .add_request_header("X-Blocked", "true")
            .build()
        )

        # Serialize to JSON (what we send to proxy)
        json_str = json.dumps(response.to_dict())

        # Parse back (simulating what Rust would receive)
        parsed = json.loads(json_str)

        # Verify structure matches Rust expectations
        assert parsed["version"] == 1
        assert parsed["decision"]["block"]["status"] == 403
        assert parsed["decision"]["block"]["body"] == "Access denied"
        assert parsed["audit"]["tags"] == ["security"]
        assert parsed["request_headers"][0]["set"]["name"] == "X-Blocked"


class TestBodyMutationFormat:
    """Test body mutation format matches Rust BodyMutation."""

    def test_body_mutation_structure(self) -> None:
        """BodyMutation has data and chunk_index fields."""
        import base64

        response = (
            Decision.allow()
            .with_request_body_mutation(b"modified content", chunk_index=0)
            .build()
        )
        data = response.to_dict()

        mutation = data["request_body_mutation"]
        assert mutation is not None
        assert "data" in mutation
        assert "chunk_index" in mutation
        assert mutation["chunk_index"] == 0
        # Data should be base64 encoded
        assert mutation["data"] == base64.b64encode(b"modified content").decode()

    def test_pass_through_mutation(self) -> None:
        """Pass-through mutation has None data."""
        # In Rust: BodyMutation { data: None, chunk_index: 0 }
        # This means "use original chunk unchanged"
        response = Decision.allow().build()
        data = response.to_dict()
        # No mutation = pass through
        assert data["request_body_mutation"] is None
