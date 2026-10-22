"""V2 Agent runner with gRPC and UDS support."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from zentinel_agent_sdk.agent import Agent
from zentinel_agent_sdk.v2.handler import AgentHandlerV2, correlation_id_of
from zentinel_agent_sdk.v2.types import HandshakeRequest
from zentinel_agent_sdk.v2.uds import MessageType, encode_json, read_frame, write_frame

logger = logging.getLogger("zentinel_agent_sdk.v2")

_UDS_EVENT_TYPES: dict[int, str] = {
    MessageType.REQUEST_HEADERS: "request_headers",
    MessageType.REQUEST_BODY_CHUNK: "request_body_chunk",
    MessageType.RESPONSE_HEADERS: "response_headers",
    MessageType.RESPONSE_BODY_CHUNK: "response_body_chunk",
    MessageType.REQUEST_COMPLETE: "request_complete",
    MessageType.WEBSOCKET_FRAME: "websocket_frame",
    MessageType.GUARDRAIL_INSPECT: "guardrail_inspect",
    MessageType.CONFIGURE: "configure",
}


class TransportType(str, Enum):
    """Transport type for v2 agents."""

    GRPC = "grpc"
    UDS = "uds"
    BOTH = "both"


@dataclass
class TransportConfig:
    """Transport configuration for v2 agents."""

    transport_type: TransportType = TransportType.UDS
    grpc_address: str = "0.0.0.0:50051"
    uds_path: Path = field(default_factory=lambda: Path("/tmp/zentinel-agent.sock"))


@dataclass
class V2RunnerConfig:
    """Configuration for the v2 agent runner."""

    transport: TransportConfig = field(default_factory=TransportConfig)
    name: str = "agent"
    json_logs: bool = False
    log_level: str = "INFO"


class AgentRunnerV2:
    """Runner for v2 Zentinel agents.

    Handles CLI parsing, logging setup, and server lifecycle for v2 protocol.
    Supports both gRPC and UDS transports.

    Example:
        class MyAgent(AgentV2):
            @property
            def name(self) -> str:
                return "my-agent"

            def capabilities(self) -> AgentCapabilities:
                return (
                    AgentCapabilities("my-agent", "My Agent", "1.0.0")
                    .with_streaming_body(True)
                    .with_flow_control(True)
                )

            async def on_request(self, request: Request) -> Decision:
                return Decision.allow()

        if __name__ == "__main__":
            runner = (
                AgentRunnerV2(MyAgent())
                .with_name("my-agent")
                .with_grpc("0.0.0.0:50051")
            )
            asyncio.run(runner.run())
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the runner with an agent.

        Args:
            agent: The agent to run: an `AgentV2`, or a plain `Agent`
                (capabilities are then derived from its name).
        """
        self._agent = agent
        self._handler = AgentHandlerV2(agent)
        self._config = V2RunnerConfig(name=agent.name)
        self._server: asyncio.Server | None = None
        self._connections: set[asyncio.StreamWriter] = set()
        self._shutdown_event = asyncio.Event()

    def with_name(self, name: str) -> AgentRunnerV2:
        """Set the agent name for logging.

        Args:
            name: The agent name.

        Returns:
            Self for chaining.
        """
        self._config.name = name
        return self

    def with_grpc(self, address: str) -> AgentRunnerV2:
        """Configure gRPC transport.

        Args:
            address: gRPC server address (e.g., "0.0.0.0:50051").

        Returns:
            Self for chaining.
        """
        self._config.transport.transport_type = TransportType.GRPC
        self._config.transport.grpc_address = address
        return self

    def with_uds(self, path: Path | str) -> AgentRunnerV2:
        """Configure Unix domain socket transport.

        Args:
            path: Path to the Unix socket.

        Returns:
            Self for chaining.
        """
        self._config.transport.transport_type = TransportType.UDS
        self._config.transport.uds_path = Path(path)
        return self

    def with_both(self, grpc_address: str, uds_path: Path | str) -> AgentRunnerV2:
        """Configure both gRPC and UDS transports.

        Args:
            grpc_address: gRPC server address.
            uds_path: Path to the Unix socket.

        Returns:
            Self for chaining.
        """
        self._config.transport.transport_type = TransportType.BOTH
        self._config.transport.grpc_address = grpc_address
        self._config.transport.uds_path = Path(uds_path)
        return self

    def with_json_logs(self) -> AgentRunnerV2:
        """Enable JSON log format.

        Returns:
            Self for chaining.
        """
        self._config.json_logs = True
        return self

    def with_log_level(self, level: str) -> AgentRunnerV2:
        """Set the log level.

        Args:
            level: The log level (DEBUG, INFO, WARNING, ERROR).

        Returns:
            Self for chaining.
        """
        self._config.log_level = level
        return self

    def with_config(self, config: V2RunnerConfig) -> AgentRunnerV2:
        """Set the full runner configuration.

        Args:
            config: The runner configuration.

        Returns:
            Self for chaining.
        """
        self._config = config
        return self

    def _setup_logging(self) -> None:
        """Configure logging based on settings."""
        import json as json_module

        level = getattr(logging, self._config.log_level.upper(), logging.INFO)

        if self._config.json_logs:

            class JsonFormatter(logging.Formatter):
                def __init__(self, agent_name: str):
                    super().__init__()
                    self._agent_name = agent_name

                def format(self, record: logging.LogRecord) -> str:
                    log_data = {
                        "timestamp": self.formatTime(record),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                        "agent": self._agent_name,
                    }
                    if record.exc_info:
                        log_data["exception"] = self.formatException(record.exc_info)
                    return json_module.dumps(log_data)

            handler = logging.StreamHandler()
            json_formatter = JsonFormatter(self._config.name)
            handler.setFormatter(json_formatter)
        else:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f"%(asctime)s [{self._config.name}] %(levelname)s: %(message)s"
            )
            handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(handler)
        root_logger.setLevel(level)
        logger.setLevel(level)

    async def _handle_uds_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Serve one proxy connection: handshake, then events.

        The proxy multiplexes requests over a connection, so events are
        handled concurrently and every response carries its correlation id
        in `audit.custom`. Configure is handled before the next message is
        read, so no request on the connection precedes its configuration.
        """
        self._connections.add(writer)
        write_lock = asyncio.Lock()
        tasks: set[asyncio.Task[None]] = set()

        async def send(msg_type: int, payload: bytes) -> None:
            async with write_lock:
                await write_frame(writer, msg_type, payload)

        async def respond(event_type: str, data: dict[str, Any]) -> None:
            response = await self._handler.dispatch(event_type, data)
            audit = response.setdefault("audit", {})
            audit.setdefault("custom", {})["correlation_id"] = correlation_id_of(data)
            await send(MessageType.AGENT_RESPONSE, encode_json(response))

        try:
            frame = await read_frame(reader)
            if frame is None:
                return
            msg_type, payload = frame
            if msg_type != MessageType.HANDSHAKE_REQUEST:
                logger.error(f"Expected a handshake request, got message type 0x{msg_type:02x}")
                return
            request = HandshakeRequest.from_dict(json.loads(payload))
            handshake = await self._handler.on_handshake(request)
            await send(MessageType.HANDSHAKE_RESPONSE, encode_json(handshake.to_dict()))
            if not handshake.success:
                return
            logger.debug(f"Handshake completed with {request.proxy_id} {request.proxy_version}")

            while not self._shutdown_event.is_set():
                frame = await read_frame(reader)
                if frame is None:
                    break
                msg_type, payload = frame
                if msg_type == MessageType.PING:
                    await send(MessageType.PONG, payload)
                    continue
                event_type = _UDS_EVENT_TYPES.get(msg_type)
                if event_type is None:
                    if msg_type != MessageType.CANCEL:
                        logger.debug(f"Ignoring message type 0x{msg_type:02x}")
                    continue
                data = json.loads(payload) if payload else {}
                if msg_type == MessageType.CONFIGURE:
                    await respond(event_type, data)
                else:
                    task = asyncio.create_task(respond(event_type, data))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
        except (ConnectionError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.exception(f"UDS connection error: {e}")
        finally:
            for task in tasks:
                task.cancel()
            self._connections.discard(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _run_uds_server(self) -> None:
        """Run the UDS server until shutdown."""
        socket_path = self._config.transport.uds_path

        # Clean up existing socket
        if socket_path.exists():
            socket_path.unlink()

        # Ensure parent directory exists
        socket_path.parent.mkdir(parents=True, exist_ok=True)

        self._server = await asyncio.start_unix_server(
            self._handle_uds_connection,
            path=str(socket_path),
        )

        # Set socket permissions
        os.chmod(socket_path, 0o660)

        logger.info(f"UDS server listening on {socket_path}")

        try:
            await self._shutdown_event.wait()
        finally:
            self._server.close()
            for writer in list(self._connections):
                writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            if socket_path.exists():
                socket_path.unlink()

    async def _run_grpc_server(self) -> None:
        """Run the gRPC server (`zentinel.agent.v2.AgentServiceV2`) until shutdown."""
        from zentinel_agent_sdk.v2.grpc_server import serve_grpc

        await serve_grpc(self._handler, self._config.transport.grpc_address, self._shutdown_event)

    async def run(self) -> None:
        """Start the v2 agent server.

        Listens on the configured transport(s) and handles connections
        until shutdown signal is received.
        """
        self._setup_logging()

        caps = self._handler.capabilities()
        logger.info(
            f"Starting v2 agent: {caps.agent_id} ({caps.name} v{caps.version})"
        )

        # Set up signal handlers
        loop = asyncio.get_running_loop()

        def handle_signal() -> None:
            logger.info("Shutdown signal received")
            self._shutdown_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, handle_signal)

        transport_type = self._config.transport.transport_type

        try:
            if transport_type == TransportType.UDS:
                await self._run_uds_server()
            elif transport_type == TransportType.GRPC:
                await self._run_grpc_server()
            elif transport_type == TransportType.BOTH:
                # Run both servers concurrently
                await asyncio.gather(
                    self._run_uds_server(),
                    self._run_grpc_server(),
                )
        except Exception as e:
            logger.exception(f"Server error: {e}")
            raise
        finally:
            logger.info("Agent shutdown complete")


def parse_v2_args() -> argparse.Namespace:
    """Parse command line arguments for v2 agents.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(description="Zentinel Agent V2")
    parser.add_argument(
        "--grpc",
        type=str,
        default=None,
        help="gRPC server address (e.g., 0.0.0.0:50051)",
    )
    parser.add_argument(
        "--socket",
        type=Path,
        default=None,
        help="Unix socket path (default /tmp/zentinel-agent.sock unless --grpc is given)",
    )
    parser.add_argument(
        "--json-logs",
        action="store_true",
        help="Enable JSON log format",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )
    return parser.parse_args()


def run_agent_v2(agent: Agent) -> None:
    """Convenience function to run a v2 agent from main.

    Parses command line arguments and runs the agent.

    Args:
        agent: The agent to run.

    `--socket PATH` serves the Unix socket, `--grpc HOST:PORT` gRPC; both
    together serve both.

    Example:
        if __name__ == "__main__":
            run_agent_v2(MyAgent())
    """
    args = parse_v2_args()

    runner = AgentRunnerV2(agent).with_name(agent.name)

    if args.grpc and args.socket:
        runner = runner.with_both(args.grpc, args.socket)
    elif args.grpc:
        runner = runner.with_grpc(args.grpc)
    else:
        runner = runner.with_uds(args.socket or Path("/tmp/zentinel-agent.sock"))

    if args.json_logs:
        runner = runner.with_json_logs()

    runner = runner.with_log_level(args.log_level)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(runner.run())
    sys.exit(0)
