"""Agent runner for plain `Agent`s.

`AgentRunner` and `run_agent` predate the `v2` package. They used to speak
the v1 framing (length plus JSON, no message type), which the proxy no longer
understands; they are now thin wrappers over `v2.AgentRunnerV2`, so every
agent speaks protocol v2.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

from zentinel_agent_sdk.agent import Agent
from zentinel_agent_sdk.v2.handler import AgentHandlerV2
from zentinel_agent_sdk.v2.runner import AgentRunnerV2

#: The v1 name of the event handler; the v2 handler serves plain agents too.
AgentHandler = AgentHandlerV2


@dataclass
class RunnerConfig:
    """Configuration for the agent runner."""

    socket_path: Path = field(default_factory=lambda: Path("/tmp/zentinel-agent.sock"))
    name: str = "agent"
    json_logs: bool = False
    log_level: str = "INFO"
    grpc_address: str | None = None


class AgentRunner:
    """Runner for starting and managing an agent over protocol v2.

    Example:
        runner = (
            AgentRunner(MyAgent())
            .with_name("my-agent")
            .with_socket(Path("/tmp/my-agent.sock"))
        )
        await runner.run()
    """

    def __init__(self, agent: Agent) -> None:
        """Initialize the runner with an agent."""
        self._agent = agent
        self._config = RunnerConfig(name=agent.name)

    def with_name(self, name: str) -> AgentRunner:
        """Set the agent name for logging."""
        self._config.name = name
        return self

    def with_socket(self, path: Path | str) -> AgentRunner:
        """Set the Unix socket path."""
        self._config.socket_path = Path(path)
        return self

    def with_grpc(self, address: str) -> AgentRunner:
        """Also serve gRPC on `address` (host:port)."""
        self._config.grpc_address = address
        return self

    def with_json_logs(self) -> AgentRunner:
        """Enable JSON log format."""
        self._config.json_logs = True
        return self

    def with_log_level(self, level: str) -> AgentRunner:
        """Set the log level (DEBUG, INFO, WARNING, ERROR)."""
        self._config.log_level = level
        return self

    def with_config(self, config: RunnerConfig) -> AgentRunner:
        """Set the full runner configuration."""
        self._config = config
        return self

    def to_v2(self) -> AgentRunnerV2:
        """The `AgentRunnerV2` this runner delegates to."""
        cfg = self._config
        runner = AgentRunnerV2(self._agent).with_name(cfg.name).with_log_level(cfg.log_level)
        if cfg.grpc_address:
            runner = runner.with_both(cfg.grpc_address, cfg.socket_path)
        else:
            runner = runner.with_uds(cfg.socket_path)
        if cfg.json_logs:
            runner = runner.with_json_logs()
        return runner

    async def run(self) -> None:
        """Serve the agent until a shutdown signal arrives."""
        await self.to_v2().run()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Zentinel Agent")
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/tmp/zentinel-agent.sock"),
        help="Unix socket path",
    )
    parser.add_argument(
        "--grpc",
        type=str,
        default=None,
        help="Also serve gRPC on this address (e.g. 127.0.0.1:50051)",
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
    """Run an agent from `main`, configured from the command line.

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
        grpc_address=args.grpc,
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(AgentRunner(agent).with_config(config).run())
    sys.exit(0)
