"""Decision builder for fluent API responses."""

from __future__ import annotations

import json
from typing import Any

from zentinel_agent_sdk.protocol import AgentResponse, AuditMetadata, HeaderOp


class Decision:
    """Fluent builder for agent decisions.

    Provides a chainable API for building agent responses with
    decisions, header mutations, and audit metadata.
    """

    def __init__(self, decision: str | dict[str, Any] = "allow") -> None:
        """Initialize a Decision.

        Args:
            decision: The decision type ("allow", or block/redirect dict).
        """
        self._decision = decision
        self._request_headers: list[HeaderOp] = []
        self._response_headers: list[HeaderOp] = []
        self._routing_metadata: dict[str, str] = {}
        self._audit = AuditMetadata()
        self._needs_more = False
        self._request_body_mutation: dict[str, Any] | None = None
        self._response_body_mutation: dict[str, Any] | None = None

    @classmethod
    def allow(cls) -> Decision:
        """Create an allow decision (pass request through).

        Returns:
            A new Decision that allows the request.
        """
        return cls("allow")

    @classmethod
    def block(cls, status: int = 403) -> Decision:
        """Create a block decision (reject with status).

        Args:
            status: The HTTP status code to return.

        Returns:
            A new Decision that blocks the request.
        """
        return cls({"block": {"status": status}})

    @classmethod
    def deny(cls) -> Decision:
        """Create a deny decision (block with 403).

        Returns:
            A new Decision that denies the request with 403.
        """
        return cls.block(403)

    @classmethod
    def unauthorized(cls) -> Decision:
        """Create an unauthorized decision (block with 401).

        Returns:
            A new Decision that returns 401 Unauthorized.
        """
        return cls.block(401)

    @classmethod
    def rate_limited(cls) -> Decision:
        """Create a rate limited decision (block with 429).

        Returns:
            A new Decision that returns 429 Too Many Requests.
        """
        return cls.block(429)

    @classmethod
    def redirect(cls, url: str, status: int = 302) -> Decision:
        """Create a redirect decision.

        Args:
            url: The URL to redirect to.
            status: The redirect status code (default 302).

        Returns:
            A new Decision that redirects the request.
        """
        return cls({"redirect": {"url": url, "status": status}})

    @classmethod
    def redirect_permanent(cls, url: str) -> Decision:
        """Create a permanent redirect decision (301).

        Args:
            url: The URL to redirect to.

        Returns:
            A new Decision with 301 redirect.
        """
        return cls.redirect(url, 301)

    @classmethod
    def challenge(
        cls, challenge_type: str, params: dict[str, Any] | None = None
    ) -> Decision:
        """Create a challenge decision (e.g., CAPTCHA).

        Args:
            challenge_type: The type of challenge (e.g., "captcha").
            params: Optional parameters for the challenge.

        Returns:
            A new Decision that challenges the request.
        """
        challenge_data: dict[str, Any] = {"challenge_type": challenge_type}
        if params:
            challenge_data["params"] = params
        return cls({"challenge": challenge_data})

    def with_body(self, body: str) -> Decision:
        """Set the response body for block decisions.

        Args:
            body: The response body string.

        Returns:
            Self for chaining.
        """
        if isinstance(self._decision, dict) and "block" in self._decision:
            self._decision["block"]["body"] = body
        return self

    def with_json_body(self, value: Any) -> Decision:
        """Set a JSON response body for block decisions.

        Args:
            value: The value to serialize as JSON.

        Returns:
            Self for chaining.
        """
        if isinstance(self._decision, dict) and "block" in self._decision:
            self._decision["block"]["body"] = json.dumps(value)
            if "headers" not in self._decision["block"]:
                self._decision["block"]["headers"] = {}
            self._decision["block"]["headers"]["Content-Type"] = "application/json"
        return self

    def with_block_header(self, name: str, value: str) -> Decision:
        """Add a header to the block response.

        Args:
            name: The header name.
            value: The header value.

        Returns:
            Self for chaining.
        """
        if isinstance(self._decision, dict) and "block" in self._decision:
            if "headers" not in self._decision["block"]:
                self._decision["block"]["headers"] = {}
            self._decision["block"]["headers"][name] = value
        return self

    def add_request_header(self, name: str, value: str) -> Decision:
        """Add a header to the upstream request.

        Args:
            name: The header name.
            value: The header value.

        Returns:
            Self for chaining.
        """
        self._request_headers.append(HeaderOp("set", name, value))
        return self

    def remove_request_header(self, name: str) -> Decision:
        """Remove a header from the upstream request.

        Args:
            name: The header name to remove.

        Returns:
            Self for chaining.
        """
        self._request_headers.append(HeaderOp("remove", name))
        return self

    def add_response_header(self, name: str, value: str) -> Decision:
        """Add a header to the client response.

        Args:
            name: The header name.
            value: The header value.

        Returns:
            Self for chaining.
        """
        self._response_headers.append(HeaderOp("set", name, value))
        return self

    def remove_response_header(self, name: str) -> Decision:
        """Remove a header from the client response.

        Args:
            name: The header name to remove.

        Returns:
            Self for chaining.
        """
        self._response_headers.append(HeaderOp("remove", name))
        return self

    def with_routing_metadata(self, key: str, value: str) -> Decision:
        """Add routing metadata.

        Args:
            key: The metadata key.
            value: The metadata value.

        Returns:
            Self for chaining.
        """
        self._routing_metadata[key] = value
        return self

    def with_tag(self, tag: str) -> Decision:
        """Add a single audit tag.

        Args:
            tag: The tag to add.

        Returns:
            Self for chaining.
        """
        self._audit.tags.append(tag)
        return self

    def with_tags(self, tags: list[str]) -> Decision:
        """Add multiple audit tags.

        Args:
            tags: The tags to add.

        Returns:
            Self for chaining.
        """
        self._audit.tags.extend(tags)
        return self

    def with_rule_id(self, rule_id: str) -> Decision:
        """Add a rule ID to audit metadata.

        Args:
            rule_id: The rule ID.

        Returns:
            Self for chaining.
        """
        self._audit.rule_ids.append(rule_id)
        return self

    def with_confidence(self, confidence: float) -> Decision:
        """Set the confidence score.

        Args:
            confidence: The confidence score (0.0 to 1.0).

        Returns:
            Self for chaining.
        """
        self._audit.confidence = confidence
        return self

    def with_reason_code(self, code: str) -> Decision:
        """Add a reason code.

        Args:
            code: The reason code.

        Returns:
            Self for chaining.
        """
        self._audit.reason_codes.append(code)
        return self

    def with_metadata(self, key: str, value: Any) -> Decision:
        """Add custom audit metadata.

        Args:
            key: The metadata key.
            value: The metadata value (must be JSON serializable).

        Returns:
            Self for chaining.
        """
        self._audit.custom[key] = value
        return self

    def needs_more_data(self) -> Decision:
        """Indicate that the agent needs more data (body chunks).

        Returns:
            Self for chaining.
        """
        self._needs_more = True
        return self

    def with_request_body_mutation(
        self, data: bytes | None, chunk_index: int = 0
    ) -> Decision:
        """Set request body mutation.

        Args:
            data: The modified body data (None = pass-through, empty = drop).
            chunk_index: The chunk index being mutated.

        Returns:
            Self for chaining.
        """
        import base64

        self._request_body_mutation = {
            "data": base64.b64encode(data).decode() if data is not None else None,
            "chunk_index": chunk_index,
        }
        return self

    def with_response_body_mutation(
        self, data: bytes | None, chunk_index: int = 0
    ) -> Decision:
        """Set response body mutation.

        Args:
            data: The modified body data (None = pass-through, empty = drop).
            chunk_index: The chunk index being mutated.

        Returns:
            Self for chaining.
        """
        import base64

        self._response_body_mutation = {
            "data": base64.b64encode(data).decode() if data is not None else None,
            "chunk_index": chunk_index,
        }
        return self

    def build(self) -> AgentResponse:
        """Build the AgentResponse.

        Returns:
            The built AgentResponse ready for transmission.
        """
        return AgentResponse(
            decision=self._decision,
            request_headers=self._request_headers,
            response_headers=self._response_headers,
            routing_metadata=self._routing_metadata,
            audit=self._audit,
            needs_more=self._needs_more,
            request_body_mutation=self._request_body_mutation,
            response_body_mutation=self._response_body_mutation,
        )


class decisions:
    """Shorthand functions for common decisions."""

    @staticmethod
    def allow() -> Decision:
        """Create an allow decision."""
        return Decision.allow()

    @staticmethod
    def deny() -> Decision:
        """Create a deny decision (403)."""
        return Decision.deny()

    @staticmethod
    def unauthorized() -> Decision:
        """Create an unauthorized decision (401)."""
        return Decision.unauthorized()

    @staticmethod
    def rate_limited() -> Decision:
        """Create a rate limited decision (429)."""
        return Decision.rate_limited()

    @staticmethod
    def block(status: int, body: str | None = None) -> Decision:
        """Create a block decision with optional body."""
        d = Decision.block(status)
        if body:
            d = d.with_body(body)
        return d

    @staticmethod
    def redirect(url: str, permanent: bool = False) -> Decision:
        """Create a redirect decision."""
        if permanent:
            return Decision.redirect_permanent(url)
        return Decision.redirect(url)
