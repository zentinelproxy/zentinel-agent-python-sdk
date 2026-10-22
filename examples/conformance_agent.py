"""The conformance agent of the Zentinel SDK conformance harness.

Implements the behaviour `sdk-conformance/README.md` in zentinelproxy/zentinel
specifies, so the harness can check this SDK against a real proxy:

    python examples/conformance_agent.py --socket /tmp/conformance.sock
    python examples/conformance_agent.py --grpc 127.0.0.1:50051
"""

from __future__ import annotations

from typing import Any

from zentinel_agent_sdk import Decision, Request, Response
from zentinel_agent_sdk.v2 import AgentCapabilities, AgentV2, run_agent_v2


class ConformanceAgent(AgentV2):
    def __init__(self) -> None:
        self._config: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "conformance"

    def capabilities(self) -> AgentCapabilities:
        return AgentCapabilities("conformance", "Conformance agent", "0.3.0").with_events(
            "request_headers", "request_body_chunk", "response_headers"
        )

    async def on_configure(self, config: dict[str, Any]) -> None:
        self._config = config

    def _config_value(self) -> str:
        nested = (self._config or {}).get("nested")
        if isinstance(nested, dict) and isinstance(nested.get("value"), str):
            return str(nested["value"])
        return "unconfigured"

    async def on_request(self, request: Request) -> Decision:
        if request.path.startswith("/block"):
            return Decision.block(403).with_body("blocked-by-agent")
        return (
            Decision.allow()
            .add_request_header("X-Hello", "from-agent")
            .add_request_header("X-Conformance-Config", self._config_value())
        )

    async def on_request_body(self, request: Request) -> Decision:
        body = request.body.decode("utf-8", "replace")
        if "block-this-body" in body:
            return Decision.block(403).with_body("body-seen:" + body)
        return Decision.allow()

    async def on_response(self, request: Request, response: Response) -> Decision:
        return Decision.allow().add_response_header("X-Conformance-Response", "from-agent")


if __name__ == "__main__":
    run_agent_v2(ConformanceAgent())
