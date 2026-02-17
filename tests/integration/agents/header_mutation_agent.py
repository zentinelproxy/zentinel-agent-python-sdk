#!/usr/bin/env python3
"""Header mutation agent for integration testing.

This agent tests header add/remove operations on both
request and response headers.
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add parent to path for imports when run directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from zentinel_agent_sdk import Agent, Decision, Request, Response
from zentinel_agent_sdk.runner import AgentRunner


class HeaderMutationAgent(Agent):
    """Agent that modifies request and response headers."""

    @property
    def name(self) -> str:
        return "header-mutation-agent"

    async def on_request(self, request: Request) -> Decision:
        """Modify request headers going to upstream."""
        decision = Decision.allow()

        # Add headers to upstream request
        decision = decision.add_request_header("X-Forwarded-By", "python-sdk")
        decision = decision.add_request_header("X-Agent-Version", "0.1.0")

        # Remove sensitive headers (if they exist)
        if request.has_header("X-Internal-Token"):
            decision = decision.remove_request_header("X-Internal-Token")

        # Add response headers
        decision = decision.add_response_header("X-Request-Processed", "true")
        decision = decision.add_response_header("X-Request-Method", request.method)

        return decision.with_tag("headers-modified")

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Modify response headers going to client."""
        decision = Decision.allow()

        # Add response headers
        decision = decision.add_response_header("X-Response-Status", str(response.status_code))
        decision = decision.add_response_header("X-Response-Processed", "true")

        # Remove server header for security
        decision = decision.remove_response_header("Server")

        return decision


def main() -> None:
    parser = argparse.ArgumentParser(description="Header Mutation Agent for testing")
    parser.add_argument("--socket", type=Path, required=True, help="Unix socket path")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    agent = HeaderMutationAgent()
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
