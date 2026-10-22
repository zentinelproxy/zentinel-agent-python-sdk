"""Agent protocol v2 over a Unix domain socket: framing and message types.

Every message is framed as::

    +----------------+--------+-----------------+
    | length (4, BE) | type   | payload (JSON)  |
    +----------------+--------+-----------------+

`length` counts the type byte and the payload. This matches
`zentinel_agent_protocol::v2::uds` in the proxy.
"""

from __future__ import annotations

import asyncio
import json
import struct
from enum import IntEnum
from typing import Any

#: Largest frame the proxy sends or accepts (16 MiB).
MAX_UDS_MESSAGE_SIZE = 16 * 1024 * 1024


class MessageType(IntEnum):
    """The type byte of a v2 UDS frame."""

    HANDSHAKE_REQUEST = 0x01
    HANDSHAKE_RESPONSE = 0x02
    REQUEST_HEADERS = 0x10
    REQUEST_BODY_CHUNK = 0x11
    RESPONSE_HEADERS = 0x12
    RESPONSE_BODY_CHUNK = 0x13
    REQUEST_COMPLETE = 0x14
    WEBSOCKET_FRAME = 0x15
    GUARDRAIL_INSPECT = 0x16
    CONFIGURE = 0x17
    AGENT_RESPONSE = 0x20
    HEALTH_STATUS = 0x30
    METRICS_REPORT = 0x31
    CONFIG_UPDATE_REQUEST = 0x32
    FLOW_CONTROL = 0x33
    CANCEL = 0x40
    PING = 0x41
    PONG = 0x42


class ProtocolError(Exception):
    """A frame that violates the v2 UDS framing."""


def encode_frame(msg_type: int, payload: bytes) -> bytes:
    """Frame a payload."""
    if len(payload) > MAX_UDS_MESSAGE_SIZE:
        raise ProtocolError(
            f"message of {len(payload)} bytes exceeds the {MAX_UDS_MESSAGE_SIZE} byte limit"
        )
    return struct.pack(">IB", len(payload) + 1, msg_type) + payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes] | None:
    """Read one frame. Returns None when the peer closed the connection."""
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0:
        raise ProtocolError("zero-length message")
    if length > MAX_UDS_MESSAGE_SIZE:
        raise ProtocolError(
            f"message of {length} bytes exceeds the {MAX_UDS_MESSAGE_SIZE} byte limit"
        )
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return body[0], body[1:]


async def write_frame(writer: asyncio.StreamWriter, msg_type: int, payload: bytes) -> None:
    """Write one frame."""
    writer.write(encode_frame(msg_type, payload))
    await writer.drain()


def encode_json(value: Any) -> bytes:
    """JSON payload encoding (the only encoding this SDK negotiates)."""
    return json.dumps(value, separators=(",", ":")).encode("utf-8")
