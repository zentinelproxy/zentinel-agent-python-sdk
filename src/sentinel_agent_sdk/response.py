"""Response wrapper for ergonomic access to HTTP response data."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from sentinel_agent_sdk.protocol import ResponseHeadersEvent

T = TypeVar("T")


class Response:
    """Ergonomic wrapper around HTTP response data.

    Provides convenient methods for accessing response properties,
    headers, and body content.
    """

    def __init__(
        self,
        event: ResponseHeadersEvent,
        body: bytes | None = None,
    ) -> None:
        """Initialize a Response from a ResponseHeadersEvent.

        Args:
            event: The response headers event from the protocol.
            body: Optional response body bytes.
        """
        self._event = event
        self._body = body or b""

    @property
    def correlation_id(self) -> str:
        """Get the correlation ID for request tracing."""
        return self._event.correlation_id

    @property
    def status_code(self) -> int:
        """Get the HTTP status code."""
        return self._event.status

    def is_success(self) -> bool:
        """Check if the status code indicates success (2xx)."""
        return 200 <= self._event.status < 300

    def is_redirect(self) -> bool:
        """Check if the status code indicates redirect (3xx)."""
        return 300 <= self._event.status < 400

    def is_client_error(self) -> bool:
        """Check if the status code indicates client error (4xx)."""
        return 400 <= self._event.status < 500

    def is_server_error(self) -> bool:
        """Check if the status code indicates server error (5xx)."""
        return 500 <= self._event.status < 600

    def is_error(self) -> bool:
        """Check if the status code indicates any error (4xx or 5xx)."""
        return self._event.status >= 400

    @property
    def headers(self) -> dict[str, list[str]]:
        """Get all headers as a dictionary."""
        return self._event.headers

    def header(self, name: str) -> str | None:
        """Get a single header value (case-insensitive).

        Args:
            name: The header name.

        Returns:
            The first value for the header, or None if not present.
        """
        name_lower = name.lower()
        for key, values in self._event.headers.items():
            if key.lower() == name_lower and values:
                return values[0]
        return None

    def header_all(self, name: str) -> list[str]:
        """Get all values for a header (case-insensitive).

        Args:
            name: The header name.

        Returns:
            All values for the header, or empty list if not present.
        """
        name_lower = name.lower()
        for key, values in self._event.headers.items():
            if key.lower() == name_lower:
                return values
        return []

    def has_header(self, name: str) -> bool:
        """Check if a header exists (case-insensitive).

        Args:
            name: The header name.

        Returns:
            True if the header exists.
        """
        name_lower = name.lower()
        return any(key.lower() == name_lower for key in self._event.headers)

    @property
    def content_type(self) -> str | None:
        """Get the Content-Type header value."""
        return self.header("content-type")

    @property
    def location(self) -> str | None:
        """Get the Location header value (for redirects)."""
        return self.header("location")

    @property
    def content_length(self) -> int | None:
        """Get the Content-Length header value as an integer."""
        value = self.header("content-length")
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def is_json(self) -> bool:
        """Check if the content type indicates JSON."""
        ct = self.content_type
        if ct is None:
            return False
        return "application/json" in ct.lower()

    def is_html(self) -> bool:
        """Check if the content type indicates HTML."""
        ct = self.content_type
        if ct is None:
            return False
        return "text/html" in ct.lower()

    @property
    def body(self) -> bytes:
        """Get the raw body bytes."""
        return self._body

    @property
    def body_str(self) -> str:
        """Get the body as a UTF-8 string."""
        return self._body.decode("utf-8", errors="replace")

    def body_json(self, type_: type[T] | None = None) -> Any:
        """Parse the body as JSON.

        Args:
            type_: Optional type hint (not enforced, for documentation).

        Returns:
            The parsed JSON value.

        Raises:
            json.JSONDecodeError: If the body is not valid JSON.
        """
        return json.loads(self._body)

    def with_body(self, body: bytes) -> Response:
        """Create a new Response with the given body.

        Args:
            body: The body bytes.

        Returns:
            A new Response instance with the body set.
        """
        return Response(self._event, body)

    def __repr__(self) -> str:
        """Return string representation."""
        return f"Response({self.status_code})"
