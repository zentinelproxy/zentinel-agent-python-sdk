"""Tests for the Zentinel Agent SDK."""

import pytest

from zentinel_agent_sdk import Agent, Decision, Request, Response
from zentinel_agent_sdk.protocol import (
    PROTOCOL_VERSION,
    RequestHeadersEvent,
    RequestMetadata,
    ResponseHeadersEvent,
)


class TestDecision:
    """Tests for the Decision builder."""

    def test_allow(self) -> None:
        """Test allow decision."""
        decision = Decision.allow()
        response = decision.build()
        assert response.decision == "allow"
        assert response.version == PROTOCOL_VERSION

    def test_deny(self) -> None:
        """Test deny decision."""
        decision = Decision.deny()
        response = decision.build()
        assert response.decision == {"block": {"status": 403}}

    def test_block_with_status(self) -> None:
        """Test block with custom status."""
        decision = Decision.block(500)
        response = decision.build()
        assert response.decision == {"block": {"status": 500}}

    def test_block_with_body(self) -> None:
        """Test block with body."""
        decision = Decision.deny().with_body("Access denied")
        response = decision.build()
        assert response.decision["block"]["body"] == "Access denied"

    def test_redirect(self) -> None:
        """Test redirect decision."""
        decision = Decision.redirect("/login")
        response = decision.build()
        assert response.decision == {"redirect": {"url": "/login", "status": 302}}

    def test_redirect_permanent(self) -> None:
        """Test permanent redirect."""
        decision = Decision.redirect_permanent("/new-path")
        response = decision.build()
        assert response.decision == {"redirect": {"url": "/new-path", "status": 301}}

    def test_add_request_header(self) -> None:
        """Test adding request header."""
        decision = Decision.allow().add_request_header("X-Test", "value")
        response = decision.build()
        assert len(response.request_headers) == 1
        assert response.request_headers[0].name == "X-Test"
        assert response.request_headers[0].value == "value"

    def test_add_response_header(self) -> None:
        """Test adding response header."""
        decision = Decision.allow().add_response_header("X-Test", "value")
        response = decision.build()
        assert len(response.response_headers) == 1
        assert response.response_headers[0].name == "X-Test"

    def test_remove_header(self) -> None:
        """Test removing header."""
        decision = Decision.allow().remove_request_header("X-Remove")
        response = decision.build()
        assert response.request_headers[0].operation == "remove"
        assert response.request_headers[0].name == "X-Remove"

    def test_audit_tags(self) -> None:
        """Test audit tags."""
        decision = Decision.deny().with_tag("security").with_tags(["blocked", "test"])
        response = decision.build()
        assert response.audit.tags == ["security", "blocked", "test"]

    def test_audit_metadata(self) -> None:
        """Test custom audit metadata."""
        decision = Decision.deny().with_metadata("client_ip", "1.2.3.4")
        response = decision.build()
        assert response.audit.custom["client_ip"] == "1.2.3.4"

    def test_chaining(self) -> None:
        """Test method chaining."""
        decision = (
            Decision.deny()
            .with_body("Blocked")
            .with_tag("security")
            .with_rule_id("RULE_001")
            .with_confidence(0.95)
            .add_response_header("X-Blocked", "true")
        )
        response = decision.build()
        assert response.decision["block"]["body"] == "Blocked"
        assert response.audit.tags == ["security"]
        assert response.audit.rule_ids == ["RULE_001"]
        assert response.audit.confidence == 0.95
        assert len(response.response_headers) == 1


class TestRequest:
    """Tests for the Request wrapper."""

    def _make_request(
        self,
        method: str = "GET",
        uri: str = "/test",
        headers: dict[str, list[str]] | None = None,
        body: bytes | None = None,
    ) -> Request:
        """Create a test request."""
        event = RequestHeadersEvent(
            metadata=RequestMetadata(
                correlation_id="test-123",
                request_id="req-456",
                client_ip="127.0.0.1",
                client_port=12345,
            ),
            method=method,
            uri=uri,
            headers=headers or {},
        )
        return Request(event, body)

    def test_method(self) -> None:
        """Test method access."""
        request = self._make_request(method="POST")
        assert request.method == "POST"
        assert request.is_post()
        assert not request.is_get()

    def test_path(self) -> None:
        """Test path access."""
        request = self._make_request(uri="/api/users?page=1")
        assert request.path == "/api/users?page=1"
        assert request.path_only == "/api/users"
        assert request.query_string == "page=1"

    def test_path_starts_with(self) -> None:
        """Test path prefix matching."""
        request = self._make_request(uri="/api/users")
        assert request.path_starts_with("/api")
        assert not request.path_starts_with("/admin")

    def test_path_equals(self) -> None:
        """Test exact path matching."""
        request = self._make_request(uri="/health")
        assert request.path_equals("/health")
        assert not request.path_equals("/healthz")

    def test_query_params(self) -> None:
        """Test query parameter access."""
        request = self._make_request(uri="/search?q=test&tag=a&tag=b")
        assert request.query("q") == "test"
        assert request.query_all("tag") == ["a", "b"]
        assert request.query("missing") is None

    def test_headers(self) -> None:
        """Test header access."""
        request = self._make_request(
            headers={
                "Content-Type": ["application/json"],
                "X-Custom": ["value1", "value2"],
            }
        )
        assert request.header("content-type") == "application/json"
        assert request.header("Content-Type") == "application/json"
        assert request.header_all("X-Custom") == ["value1", "value2"]
        assert request.has_header("Content-Type")
        assert not request.has_header("Missing")

    def test_common_headers(self) -> None:
        """Test common header shortcuts."""
        request = self._make_request(
            headers={
                "Host": ["example.com"],
                "User-Agent": ["TestAgent/1.0"],
                "Content-Type": ["application/json"],
                "Authorization": ["Bearer token"],
                "Content-Length": ["100"],
            }
        )
        assert request.host == "example.com"
        assert request.user_agent == "TestAgent/1.0"
        assert request.content_type == "application/json"
        assert request.authorization == "Bearer token"
        assert request.content_length == 100

    def test_body(self) -> None:
        """Test body access."""
        body = b'{"key": "value"}'
        request = self._make_request(body=body)
        assert request.body == body
        assert request.body_str == '{"key": "value"}'
        assert request.body_json() == {"key": "value"}

    def test_metadata(self) -> None:
        """Test metadata access."""
        request = self._make_request()
        assert request.correlation_id == "test-123"
        assert request.client_ip == "127.0.0.1"


class TestResponse:
    """Tests for the Response wrapper."""

    def _make_response(
        self,
        status: int = 200,
        headers: dict[str, list[str]] | None = None,
        body: bytes | None = None,
    ) -> Response:
        """Create a test response."""
        event = ResponseHeadersEvent(
            correlation_id="test-123",
            status=status,
            headers=headers or {},
        )
        return Response(event, body)

    def test_status(self) -> None:
        """Test status code access."""
        assert self._make_response(200).is_success()
        assert self._make_response(302).is_redirect()
        assert self._make_response(404).is_client_error()
        assert self._make_response(500).is_server_error()
        assert self._make_response(400).is_error()
        assert self._make_response(500).is_error()

    def test_headers(self) -> None:
        """Test header access."""
        response = self._make_response(
            headers={
                "Content-Type": ["text/html"],
                "Location": ["https://example.com"],
            }
        )
        assert response.content_type == "text/html"
        assert response.location == "https://example.com"
        assert response.is_html()
        assert not response.is_json()

    def test_body(self) -> None:
        """Test body access."""
        body = b"Hello, World!"
        response = self._make_response(body=body)
        assert response.body == body
        assert response.body_str == "Hello, World!"


class TestAgent:
    """Tests for the Agent base class."""

    @pytest.mark.asyncio
    async def test_default_handlers(self) -> None:
        """Test that default handlers return allow."""

        class TestAgent(Agent):
            @property
            def name(self) -> str:
                return "test-agent"

        agent = TestAgent()

        # Create test request
        event = RequestHeadersEvent(
            metadata=RequestMetadata(
                correlation_id="test",
                request_id="req",
                client_ip="127.0.0.1",
                client_port=1234,
            ),
            method="GET",
            uri="/test",
            headers={},
        )
        request = Request(event)

        decision = await agent.on_request(request)
        response = decision.build()
        assert response.decision == "allow"
