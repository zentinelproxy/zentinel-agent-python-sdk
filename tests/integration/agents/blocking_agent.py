#!/usr/bin/env python3
"""Blocking agent for integration testing.

This agent blocks requests to specific paths, useful for testing
that the SDK correctly communicates block decisions to Zentinel.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add parent to path for imports when run directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from zentinel_agent_sdk import Agent, Decision, Request
from zentinel_agent_sdk.runner import AgentRunner


class BlockingAgent(Agent):
    """Agent that blocks requests to configured paths."""

    def __init__(self, blocked_paths: list[str] | None = None) -> None:
        self._blocked_paths = blocked_paths or ["/blocked", "/admin", "/secret"]

    @property
    def name(self) -> str:
        return "blocking-agent"

    async def on_request(self, request: Request) -> Decision:
        """Block requests to configured paths."""
        for blocked_path in self._blocked_paths:
            if request.path_starts_with(blocked_path):
                return (
                    Decision.deny()
                    .with_body(json.dumps({
                        "error": "blocked",
                        "path": request.path_only,
                        "blocked_by": "python-blocking-agent",
                    }))
                    .with_block_header("Content-Type", "application/json")
                    .with_block_header("X-Blocked-By", "python-blocking-agent")
                    .with_tag("blocked")
                    .with_rule_id("BLOCK_PATH")
                    .with_reason_code("PATH_BLOCKED")
                    .with_metadata("blocked_path", blocked_path)
                )

        # Allow with tracking header
        return (
            Decision.allow()
            .add_response_header("X-Blocking-Agent", "checked")
            .with_tag("allowed")
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Blocking Agent for testing")
    parser.add_argument("--socket", type=Path, required=True, help="Unix socket path")
    parser.add_argument(
        "--blocked-paths",
        nargs="+",
        default=["/blocked", "/admin", "/secret"],
        help="Paths to block",
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    agent = BlockingAgent(blocked_paths=args.blocked_paths)
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
