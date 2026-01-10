#!/usr/bin/env python3
"""Echo agent for integration testing.

This agent echoes request information back as response headers,
similar to the Rust echo agent used in Sentinel's test suite.
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add parent to path for imports when run directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from sentinel_agent_sdk import Agent, Decision, Request, Response
from sentinel_agent_sdk.runner import AgentRunner


class EchoAgent(Agent):
    """Agent that echoes request information as response headers."""

    def __init__(self, prefix: str = "X-Echo-") -> None:
        self._prefix = prefix

    @property
    def name(self) -> str:
        return "echo-agent"

    async def on_request(self, request: Request) -> Decision:
        """Echo request info as headers to be added to the response."""
        return (
            Decision.allow()
            .add_response_header(f"{self._prefix}Agent", "python-echo-agent")
            .add_response_header(f"{self._prefix}Method", request.method)
            .add_response_header(f"{self._prefix}Path", request.path_only)
            .add_response_header(f"{self._prefix}Correlation-Id", request.correlation_id)
            .add_response_header(f"{self._prefix}Client-Ip", request.client_ip)
            .with_tag("echo")
            .with_metadata("sdk", "python")
        )

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Add response status to headers."""
        return (
            Decision.allow()
            .add_response_header(f"{self._prefix}Upstream-Status", str(response.status_code))
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Echo Agent for testing")
    parser.add_argument("--socket", type=Path, required=True, help="Unix socket path")
    parser.add_argument("--prefix", default="X-Echo-", help="Header prefix")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    agent = EchoAgent(prefix=args.prefix)
    runner = (
        AgentRunner(agent)
        .with_socket(args.socket)
        .with_log_level(args.log_level)
    )

    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
