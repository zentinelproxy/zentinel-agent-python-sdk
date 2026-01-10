#!/usr/bin/env python3
"""Configurable Sentinel agent example.

This example demonstrates an agent with typed configuration that:
- Accepts rate limit configuration from the proxy
- Tracks request counts per client IP
- Rate limits clients exceeding the threshold
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sentinel_agent_sdk import (
    ConfigurableAgent,
    Decision,
    Request,
    Response,
    run_agent,
)


@dataclass
class RateLimitConfig:
    """Configuration for the rate limiting agent."""

    enabled: bool = True
    requests_per_minute: int = 100
    blocked_paths: list[str] = field(default_factory=list)


class RateLimitAgent(ConfigurableAgent[RateLimitConfig]):
    """An agent that rate limits requests per client IP."""

    def __init__(self) -> None:
        super().__init__(RateLimitConfig())
        self._request_counts: dict[str, int] = defaultdict(int)
        self._reset_task: asyncio.Task[None] | None = None

    @property
    def name(self) -> str:
        return "rate-limit-agent"

    def parse_config(self, config_dict: dict[str, Any]) -> RateLimitConfig:
        """Parse configuration from dictionary."""
        return RateLimitConfig(
            enabled=config_dict.get("enabled", True),
            requests_per_minute=config_dict.get("requests_per_minute", 100),
            blocked_paths=config_dict.get("blocked_paths", []),
        )

    async def on_config_applied(self, config: RateLimitConfig) -> None:
        """Called after configuration is applied."""
        print(f"Configuration applied: {config}")

        # Start reset task if not running
        if self._reset_task is None:
            self._reset_task = asyncio.create_task(self._reset_counts())

    async def _reset_counts(self) -> None:
        """Reset request counts every minute."""
        while True:
            await asyncio.sleep(60)
            self._request_counts.clear()

    async def on_request(self, request: Request) -> Decision:
        """Process incoming requests with rate limiting."""
        config = self.config

        # Check if agent is enabled
        if not config.enabled:
            return Decision.allow()

        # Check blocked paths
        for blocked_path in config.blocked_paths:
            if request.path_starts_with(blocked_path):
                return (
                    Decision.deny()
                    .with_body(f"Path {blocked_path} is blocked")
                    .with_tag("blocked_path")
                )

        # Check rate limit
        client_ip = request.client_ip
        self._request_counts[client_ip] += 1

        if self._request_counts[client_ip] > config.requests_per_minute:
            return (
                Decision.rate_limited()
                .with_body("Rate limit exceeded")
                .with_tag("rate_limited")
                .with_metadata("client_ip", client_ip)
                .with_metadata("request_count", self._request_counts[client_ip])
                .with_metadata("limit", config.requests_per_minute)
            )

        # Allow with rate limit headers
        remaining = config.requests_per_minute - self._request_counts[client_ip]
        return (
            Decision.allow()
            .add_response_header("X-RateLimit-Limit", str(config.requests_per_minute))
            .add_response_header("X-RateLimit-Remaining", str(remaining))
        )

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Add rate limit headers to response."""
        return Decision.allow()


if __name__ == "__main__":
    run_agent(RateLimitAgent())
