"""Protocol definitions for Zentinel agent communication."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

PROTOCOL_VERSION = 2
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB


class EventType(str, Enum):
    """Event types sent from proxy to agent."""

    REQUEST_HEADERS = "request_headers"
    REQUEST_BODY_CHUNK = "request_body_chunk"
    RESPONSE_HEADERS = "response_headers"
    RESPONSE_BODY_CHUNK = "response_body_chunk"
    REQUEST_COMPLETE = "request_complete"
    WEBSOCKET_FRAME = "websocket_frame"
    CONFIGURE = "configure"
    GUARDRAIL_INSPECT = "guardrail_inspect"


class GuardrailInspectionType(str, Enum):
    """Type of guardrail inspection to perform."""

    PROMPT_INJECTION = "prompt_injection"
    PII_DETECTION = "pii_detection"


class DetectionSeverity(str, Enum):
    """Severity level for guardrail detections."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RequestMetadata:
    """Metadata about the request being processed."""

    correlation_id: str
    request_id: str
    client_ip: str
    client_port: int
    server_name: str | None = None
    protocol: str = "HTTP/1.1"
    tls_version: str | None = None
    tls_cipher: str | None = None
    route_id: str | None = None
    upstream_id: str | None = None
    timestamp: str | None = None
    traceparent: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestMetadata:
        """Create from dictionary."""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            request_id=data.get("request_id", ""),
            client_ip=data.get("client_ip", ""),
            client_port=data.get("client_port", 0),
            server_name=data.get("server_name"),
            protocol=data.get("protocol", "HTTP/1.1"),
            tls_version=data.get("tls_version"),
            tls_cipher=data.get("tls_cipher"),
            route_id=data.get("route_id"),
            upstream_id=data.get("upstream_id"),
            timestamp=data.get("timestamp"),
            traceparent=data.get("traceparent"),
        )


@dataclass
class RequestHeadersEvent:
    """Event for incoming request headers."""

    metadata: RequestMetadata
    method: str
    uri: str
    headers: dict[str, list[str]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestHeadersEvent:
        """Create from dictionary."""
        return cls(
            metadata=RequestMetadata.from_dict(data.get("metadata", {})),
            method=data.get("method", "GET"),
            uri=data.get("uri", "/"),
            headers=data.get("headers", {}),
        )


@dataclass
class RequestBodyChunkEvent:
    """Event for request body chunks."""

    correlation_id: str
    data: bytes
    chunk_index: int
    is_last: bool
    total_size: int | None = None
    bytes_received: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestBodyChunkEvent:
        """Create from dictionary."""
        raw_data = data.get("data", "")
        decoded = base64.b64decode(raw_data) if raw_data else b""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            data=decoded,
            chunk_index=data.get("chunk_index", 0),
            is_last=data.get("is_last", True),
            total_size=data.get("total_size"),
            bytes_received=data.get("bytes_received", 0),
        )


@dataclass
class ResponseHeadersEvent:
    """Event for response headers from upstream."""

    correlation_id: str
    status: int
    headers: dict[str, list[str]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseHeadersEvent:
        """Create from dictionary."""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            status=data.get("status", 200),
            headers=data.get("headers", {}),
        )


@dataclass
class ResponseBodyChunkEvent:
    """Event for response body chunks."""

    correlation_id: str
    data: bytes
    chunk_index: int
    is_last: bool
    total_size: int | None = None
    bytes_received: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseBodyChunkEvent:
        """Create from dictionary."""
        raw_data = data.get("data", "")
        decoded = base64.b64decode(raw_data) if raw_data else b""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            data=decoded,
            chunk_index=data.get("chunk_index", 0),
            is_last=data.get("is_last", True),
            total_size=data.get("total_size"),
            bytes_received=data.get("bytes_received", 0),
        )


@dataclass
class RequestCompleteEvent:
    """Event when request processing is complete."""

    correlation_id: str
    status: int
    duration_ms: int
    request_size: int
    response_size: int
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestCompleteEvent:
        """Create from dictionary."""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            status=data.get("status", 0),
            duration_ms=data.get("duration_ms", 0),
            request_size=data.get("request_size", 0),
            response_size=data.get("response_size", 0),
            error=data.get("error"),
        )


@dataclass
class WebSocketFrameEvent:
    """Event for WebSocket frames."""

    correlation_id: str
    opcode: int
    data: bytes
    direction: str  # "client_to_server" or "server_to_client"
    frame_index: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebSocketFrameEvent:
        """Create from dictionary."""
        raw_data = data.get("data", "")
        decoded = base64.b64decode(raw_data) if raw_data else b""
        return cls(
            correlation_id=data.get("correlation_id", ""),
            opcode=data.get("opcode", 1),
            data=decoded,
            direction=data.get("direction", "client_to_server"),
            frame_index=data.get("frame_index", 0),
        )


@dataclass
class ConfigureEvent:
    """Event for agent configuration."""

    agent_id: str
    config: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfigureEvent:
        """Create from dictionary."""
        return cls(
            agent_id=data.get("agent_id", ""),
            config=data.get("config", {}),
        )


@dataclass
class TextSpan:
    """Text span indicating location in content."""

    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {"start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TextSpan:
        """Create from dictionary."""
        return cls(
            start=data.get("start", 0),
            end=data.get("end", 0),
        )


@dataclass
class GuardrailDetection:
    """A single guardrail detection (prompt injection attempt, PII instance, etc.)."""

    category: str
    description: str
    severity: DetectionSeverity = DetectionSeverity.MEDIUM
    confidence: float | None = None
    span: TextSpan | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "category": self.category,
            "description": self.description,
            "severity": self.severity.value,
        }
        if self.confidence is not None:
            result["confidence"] = self.confidence
        if self.span is not None:
            result["span"] = self.span.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardrailDetection:
        """Create from dictionary."""
        severity_str = data.get("severity", "medium")
        try:
            severity = DetectionSeverity(severity_str)
        except ValueError:
            severity = DetectionSeverity.MEDIUM

        span = None
        if "span" in data and data["span"]:
            span = TextSpan.from_dict(data["span"])

        return cls(
            category=data.get("category", ""),
            description=data.get("description", ""),
            severity=severity,
            confidence=data.get("confidence"),
            span=span,
        )

    def with_severity(self, severity: DetectionSeverity) -> GuardrailDetection:
        """Set severity level."""
        self.severity = severity
        return self

    def with_confidence(self, confidence: float) -> GuardrailDetection:
        """Set confidence score."""
        self.confidence = confidence
        return self

    def with_span(self, start: int, end: int) -> GuardrailDetection:
        """Set text span location."""
        self.span = TextSpan(start=start, end=end)
        return self


@dataclass
class GuardrailInspectEvent:
    """Event for guardrail content inspection."""

    correlation_id: str
    inspection_type: GuardrailInspectionType
    content: str
    model: str | None = None
    categories: list[str] = field(default_factory=list)
    route_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardrailInspectEvent:
        """Create from dictionary."""
        inspection_type_str = data.get("inspection_type", "prompt_injection")
        try:
            inspection_type = GuardrailInspectionType(inspection_type_str)
        except ValueError:
            inspection_type = GuardrailInspectionType.PROMPT_INJECTION

        return cls(
            correlation_id=data.get("correlation_id", ""),
            inspection_type=inspection_type,
            content=data.get("content", ""),
            model=data.get("model"),
            categories=data.get("categories", []),
            route_id=data.get("route_id"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class GuardrailResponse:
    """Response from guardrail inspection."""

    detected: bool = False
    confidence: float = 0.0
    detections: list[GuardrailDetection] = field(default_factory=list)
    redacted_content: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "detected": self.detected,
            "confidence": self.confidence,
            "detections": [d.to_dict() for d in self.detections],
        }
        if self.redacted_content is not None:
            result["redacted_content"] = self.redacted_content
        return result

    @classmethod
    def clean(cls) -> GuardrailResponse:
        """Create a response indicating nothing detected."""
        return cls()

    @classmethod
    def with_detection(cls, detection: GuardrailDetection) -> GuardrailResponse:
        """Create a response with a single detection."""
        return cls(
            detected=True,
            confidence=detection.confidence or 1.0,
            detections=[detection],
        )

    def add_detection(self, detection: GuardrailDetection) -> GuardrailResponse:
        """Add a detection to the response."""
        self.detected = True
        if detection.confidence is not None:
            self.confidence = max(self.confidence, detection.confidence)
        self.detections.append(detection)
        return self

    def with_redacted_content(self, content: str) -> GuardrailResponse:
        """Set redacted content for PII detection."""
        self.redacted_content = content
        return self


@dataclass
class HeaderOp:
    """Header operation for request/response modification."""

    operation: str  # "set", "add", or "remove"
    name: str
    value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        if self.operation == "remove":
            return {"remove": {"name": self.name}}
        return {self.operation: {"name": self.name, "value": self.value or ""}}


@dataclass
class AuditMetadata:
    """Audit metadata for logging and observability."""

    tags: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    confidence: float | None = None
    reason_codes: list[str] = field(default_factory=list)
    custom: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {}
        if self.tags:
            result["tags"] = self.tags
        if self.rule_ids:
            result["rule_ids"] = self.rule_ids
        if self.confidence is not None:
            result["confidence"] = self.confidence
        if self.reason_codes:
            result["reason_codes"] = self.reason_codes
        if self.custom:
            result["custom"] = self.custom
        return result


@dataclass
class AgentResponse:
    """Response from agent to proxy."""

    version: int = PROTOCOL_VERSION
    decision: str | dict[str, Any] = "allow"
    request_headers: list[HeaderOp] = field(default_factory=list)
    response_headers: list[HeaderOp] = field(default_factory=list)
    routing_metadata: dict[str, str] = field(default_factory=dict)
    audit: AuditMetadata = field(default_factory=AuditMetadata)
    needs_more: bool = False
    request_body_mutation: dict[str, Any] | None = None
    response_body_mutation: dict[str, Any] | None = None
    websocket_decision: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "decision": self.decision,
            "request_headers": [h.to_dict() for h in self.request_headers],
            "response_headers": [h.to_dict() for h in self.response_headers],
            "routing_metadata": self.routing_metadata,
            "audit": self.audit.to_dict(),
            "needs_more": self.needs_more,
            "request_body_mutation": self.request_body_mutation,
            "response_body_mutation": self.response_body_mutation,
            "websocket_decision": self.websocket_decision,
        }


def encode_message(data: dict[str, Any]) -> bytes:
    """Encode a message with length prefix for socket transmission."""
    json_bytes = json.dumps(data).encode("utf-8")
    length = len(json_bytes)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message size {length} exceeds maximum {MAX_MESSAGE_SIZE}")
    return struct.pack(">I", length) + json_bytes


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode a length-prefixed JSON message."""
    if len(data) < 4:
        raise ValueError("Message too short to contain length prefix")
    length = struct.unpack(">I", data[:4])[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message size {length} exceeds maximum {MAX_MESSAGE_SIZE}")
    json_bytes = data[4 : 4 + length]
    return json.loads(json_bytes.decode("utf-8"))


async def read_message(reader: Any) -> dict[str, Any] | None:
    """Read a length-prefixed message from an async reader."""
    length_bytes = await reader.read(4)
    if not length_bytes or len(length_bytes) < 4:
        return None

    length = struct.unpack(">I", length_bytes)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message size {length} exceeds maximum {MAX_MESSAGE_SIZE}")

    data = await reader.read(length)
    if len(data) < length:
        raise ValueError(f"Incomplete message: expected {length}, got {len(data)}")

    return json.loads(data.decode("utf-8"))


async def write_message(writer: Any, data: dict[str, Any]) -> None:
    """Write a length-prefixed message to an async writer."""
    encoded = encode_message(data)
    writer.write(encoded)
    await writer.drain()
