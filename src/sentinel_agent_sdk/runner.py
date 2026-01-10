"""Agent runner for handling connections and events."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel_agent_sdk.agent import Agent
from sentinel_agent_sdk.decision import Decision
from sentinel_agent_sdk.protocol import (
    ConfigureEvent,
    EventType,
    GuardrailInspectEvent,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent,
    read_message,
    write_message,
)
from sentinel_agent_sdk.request import Request
from sentinel_agent_sdk.response import Response

logger = logging.getLogger("sentinel_agent_sdk")


@dataclass
class RunnerConfig:
    """Configuration for the agent runner."""

    socket_path: Path = field(default_factory=lambda: Path("/tmp/sentinel-agent.sock"))
    name: str = "agent"
    json_logs: bool = False
    log_level: str = "INFO"


class AgentHandler:
    """Handles protocol events and routes them to the agent.

    Manages request caching for correlation between request and response events.
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the handler.

        Args:
            agent: The agent to route events to.
        """
        self._agent = agent
        self._requests: dict[str, Request] = {}
        self._request_bodies: dict[str, bytes] = {}
        self._response_bodies: dict[str, bytes] = {}

    async def handle_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Handle an incoming protocol event.

        Args:
            event: The protocol event dictionary.

        Returns:
            The response dictionary to send back.
        """
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        try:
            if event_type == EventType.CONFIGURE.value:
                return await self._handle_configure(payload)
            elif event_type == EventType.REQUEST_HEADERS.value:
                return await self._handle_request_headers(payload)
            elif event_type == EventType.REQUEST_BODY_CHUNK.value:
                return await self._handle_request_body_chunk(payload)
            elif event_type == EventType.RESPONSE_HEADERS.value:
                return await self._handle_response_headers(payload)
            elif event_type == EventType.RESPONSE_BODY_CHUNK.value:
                return await self._handle_response_body_chunk(payload)
            elif event_type == EventType.REQUEST_COMPLETE.value:
                return await self._handle_request_complete(payload)
            elif event_type == EventType.GUARDRAIL_INSPECT.value:
                return await self._handle_guardrail_inspect(payload)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                return Decision.allow().build().to_dict()
        except Exception as e:
            logger.exception(f"Error handling event {event_type}: {e}")
            return Decision.allow().build().to_dict()

    async def _handle_configure(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle configuration event."""
        event = ConfigureEvent.from_dict(payload)
        try:
            await self._agent.on_configure(event.config)
            logger.info(f"Agent configured: {event.agent_id}")
            return {"success": True}
        except Exception as e:
            logger.error(f"Configuration failed: {e}")
            return {"success": False, "error": str(e)}

    async def _handle_request_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle request headers event."""
        event = RequestHeadersEvent.from_dict(payload)
        request = Request(event)

        # Cache request for response correlation
        self._requests[event.metadata.correlation_id] = request
        self._request_bodies[event.metadata.correlation_id] = b""

        decision = await self._agent.on_request(request)
        return decision.build().to_dict()

    async def _handle_request_body_chunk(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle request body chunk event."""
        event = RequestBodyChunkEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Accumulate body chunks
        if correlation_id in self._request_bodies:
            self._request_bodies[correlation_id] += event.data

        # Only call handler on last chunk
        if event.is_last and correlation_id in self._requests:
            request = self._requests[correlation_id].with_body(
                self._request_bodies.get(correlation_id, b"")
            )
            decision = await self._agent.on_request_body(request)
            return decision.build().to_dict()

        # For non-final chunks, return allow with needs_more
        return Decision.allow().needs_more_data().build().to_dict()

    async def _handle_response_headers(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle response headers event."""
        event = ResponseHeadersEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Get cached request
        request = self._requests.get(correlation_id)
        if request is None:
            logger.warning(f"No cached request for correlation_id: {correlation_id}")
            return Decision.allow().build().to_dict()

        response = Response(event)
        self._response_bodies[correlation_id] = b""

        decision = await self._agent.on_response(request, response)
        return decision.build().to_dict()

    async def _handle_response_body_chunk(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle response body chunk event."""
        event = ResponseBodyChunkEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Accumulate body chunks
        if correlation_id in self._response_bodies:
            self._response_bodies[correlation_id] += event.data

        # Only call handler on last chunk
        if event.is_last and correlation_id in self._requests:
            request = self._requests[correlation_id]
            # Create response with body
            response_event = ResponseHeadersEvent(
                correlation_id=correlation_id,
                status=200,  # We don't have status here, use default
                headers={},
            )
            response = Response(response_event).with_body(
                self._response_bodies.get(correlation_id, b"")
            )
            decision = await self._agent.on_response_body(request, response)
            return decision.build().to_dict()

        return Decision.allow().needs_more_data().build().to_dict()

    async def _handle_request_complete(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle request complete event."""
        event = RequestCompleteEvent.from_dict(payload)
        correlation_id = event.correlation_id

        # Get and cleanup cached request
        request = self._requests.pop(correlation_id, None)
        self._request_bodies.pop(correlation_id, None)
        self._response_bodies.pop(correlation_id, None)

        if request is not None:
            await self._agent.on_request_complete(
                request, event.status, event.duration_ms
            )

        return {"success": True}

    async def _handle_guardrail_inspect(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle guardrail inspection event."""
        event = GuardrailInspectEvent.from_dict(payload)
        response = await self._agent.on_guardrail_inspect(event)
        return response.to_dict()


class AgentRunner:
    """Runner for starting and managing an agent.

    Uses builder pattern for configuration.

    Example:
        runner = (
            AgentRunner(MyAgent())
            .with_name("my-agent")
            .with_socket(Path("/tmp/my-agent.sock"))
        )
        await runner.run()
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the runner with an agent.

        Args:
            agent: The agent to run.
        """
        self._agent = agent
        self._config = RunnerConfig(name=agent.name)
        self._server: asyncio.Server | None = None
        self._shutdown_event = asyncio.Event()

    def with_name(self, name: str) -> AgentRunner:
        """Set the agent name for logging.

        Args:
            name: The agent name.

        Returns:
            Self for chaining.
        """
        self._config.name = name
        return self

    def with_socket(self, path: Path | str) -> AgentRunner:
        """Set the Unix socket path.

        Args:
            path: The socket path.

        Returns:
            Self for chaining.
        """
        self._config.socket_path = Path(path)
        return self

    def with_json_logs(self) -> AgentRunner:
        """Enable JSON log format.

        Returns:
            Self for chaining.
        """
        self._config.json_logs = True
        return self

    def with_log_level(self, level: str) -> AgentRunner:
        """Set the log level.

        Args:
            level: The log level (DEBUG, INFO, WARNING, ERROR).

        Returns:
            Self for chaining.
        """
        self._config.log_level = level
        return self

    def with_config(self, config: RunnerConfig) -> AgentRunner:
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
        level = getattr(logging, self._config.log_level.upper(), logging.INFO)

        if self._config.json_logs:
            import json

            class JsonFormatter(logging.Formatter):
                def format(self, record: logging.LogRecord) -> str:
                    log_data = {
                        "timestamp": self.formatTime(record),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                        "agent": self._config.name if hasattr(self, "_config") else "",
                    }
                    if record.exc_info:
                        log_data["exception"] = self.formatException(record.exc_info)
                    return json.dumps(log_data)

            handler = logging.StreamHandler()
            formatter = JsonFormatter()
            formatter._config = self._config  # type: ignore
            handler.setFormatter(formatter)
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

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single connection from the proxy."""
        handler = AgentHandler(self._agent)
        peer = writer.get_extra_info("peername")
        logger.debug(f"Connection from {peer}")

        try:
            while not self._shutdown_event.is_set():
                message = await read_message(reader)
                if message is None:
                    break

                response = await handler.handle_event(message)
                await write_message(writer, response)
        except Exception as e:
            logger.exception(f"Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f"Connection closed: {peer}")

    async def run(self) -> None:
        """Start the agent server.

        Listens on the configured Unix socket and handles connections
        until shutdown signal is received.
        """
        self._setup_logging()

        # Clean up existing socket
        socket_path = self._config.socket_path
        if socket_path.exists():
            socket_path.unlink()

        # Ensure parent directory exists
        socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Set up signal handlers
        loop = asyncio.get_running_loop()

        def handle_signal() -> None:
            logger.info("Shutdown signal received")
            self._shutdown_event.set()
            if self._server:
                self._server.close()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, handle_signal)

        # Start server
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(socket_path),
        )

        # Set socket permissions (readable/writable by owner and group)
        os.chmod(socket_path, 0o660)

        logger.info(f"Agent '{self._config.name}' listening on {socket_path}")

        async with self._server:
            try:
                await self._server.serve_forever()
            except asyncio.CancelledError:
                pass

        # Cleanup
        if socket_path.exists():
            socket_path.unlink()

        logger.info("Agent shutdown complete")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(description="Sentinel Agent")
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/tmp/sentinel-agent.sock"),
        help="Unix socket path",
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


def run_agent(agent: Agent) -> None:
    """Convenience function to run an agent from main.

    Parses command line arguments and runs the agent.

    Args:
        agent: The agent to run.

    Example:
        if __name__ == "__main__":
            run_agent(MyAgent())
    """
    args = parse_args()

    config = RunnerConfig(
        socket_path=args.socket,
        name=agent.name,
        json_logs=args.json_logs,
        log_level=args.log_level,
    )

    runner = AgentRunner(agent).with_config(config)

    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        pass
    sys.exit(0)
