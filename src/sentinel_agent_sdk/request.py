"""Request wrapper for ergonomic access to HTTP request data."""

from __future__ import annotations

import json
from typing import Any, TypeVar
from urllib.parse import parse_qs, urlparse

from sentinel_agent_sdk.protocol import RequestHeadersEvent, RequestMetadata

T = TypeVar("T")


class Request:
    """Ergonomic wrapper around HTTP request data.

    Provides convenient methods for accessing request properties,
    headers, query parameters, and body content.
    """

    def __init__(
        self,
        event: RequestHeadersEvent,
        body: bytes | None = None,
    ) -> None:
        """Initialize a Request from a RequestHeadersEvent.

        Args:
            event: The request headers event from the protocol.
            body: Optional request body bytes.
        """
        self._event = event
        self._body = body or b""
        self._parsed_uri = urlparse(event.uri)
        self._query_params: dict[str, list[str]] | None = None

    @property
    def metadata(self) -> RequestMetadata:
        """Get the request metadata."""
        return self._event.metadata

    @property
    def correlation_id(self) -> str:
        """Get the correlation ID for request tracing."""
        return self._event.metadata.correlation_id

    @property
    def client_ip(self) -> str:
        """Get the client IP address."""
        return self._event.metadata.client_ip

    @property
    def method(self) -> str:
        """Get the HTTP method."""
        return self._event.method

    def is_get(self) -> bool:
        """Check if this is a GET request."""
        return self._event.method.upper() == "GET"

    def is_post(self) -> bool:
        """Check if this is a POST request."""
        return self._event.method.upper() == "POST"

    def is_put(self) -> bool:
        """Check if this is a PUT request."""
        return self._event.method.upper() == "PUT"

    def is_delete(self) -> bool:
        """Check if this is a DELETE request."""
        return self._event.method.upper() == "DELETE"

    def is_patch(self) -> bool:
        """Check if this is a PATCH request."""
        return self._event.method.upper() == "PATCH"

    @property
    def uri(self) -> str:
        """Get the full URI including query string."""
        return self._event.uri

    @property
    def path(self) -> str:
        """Get the full path including query string."""
        return self._event.uri

    @property
    def path_only(self) -> str:
        """Get just the path without query string."""
        return self._parsed_uri.path

    @property
    def query_string(self) -> str:
        """Get the raw query string."""
        return self._parsed_uri.query

    def _get_query_params(self) -> dict[str, list[str]]:
        """Parse and cache query parameters."""
        if self._query_params is None:
            self._query_params = parse_qs(self._parsed_uri.query)
        return self._query_params

    def query(self, name: str) -> str | None:
        """Get a single query parameter value.

        Args:
            name: The parameter name.

        Returns:
            The first value for the parameter, or None if not present.
        """
        params = self._get_query_params()
        values = params.get(name)
        return values[0] if values else None

    def query_all(self, name: str) -> list[str]:
        """Get all values for a query parameter.

        Args:
            name: The parameter name.

        Returns:
            All values for the parameter, or empty list if not present.
        """
        return self._get_query_params().get(name, [])

    def path_starts_with(self, prefix: str) -> bool:
        """Check if the path starts with the given prefix.

        Args:
            prefix: The prefix to check.

        Returns:
            True if the path starts with the prefix.
        """
        return self.path_only.startswith(prefix)

    def path_equals(self, path: str) -> bool:
        """Check if the path exactly matches.

        Args:
            path: The path to compare.

        Returns:
            True if the path matches exactly.
        """
        return self.path_only == path

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
    def host(self) -> str | None:
        """Get the Host header value."""
        return self.header("host")

    @property
    def user_agent(self) -> str | None:
        """Get the User-Agent header value."""
        return self.header("user-agent")

    @property
    def content_type(self) -> str | None:
        """Get the Content-Type header value."""
        return self.header("content-type")

    @property
    def authorization(self) -> str | None:
        """Get the Authorization header value."""
        return self.header("authorization")

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

    def with_body(self, body: bytes) -> Request:
        """Create a new Request with the given body.

        Args:
            body: The body bytes.

        Returns:
            A new Request instance with the body set.
        """
        return Request(self._event, body)

    def __repr__(self) -> str:
        """Return string representation."""
        return f"Request({self.method} {self.path})"
