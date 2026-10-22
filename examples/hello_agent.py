"""The README quick-start agent: adds X-Hello and allows.

Kept identical to the README (apart from taking the socket path as an
argument), so CI can run it through the conformance harness.
"""

import asyncio
import sys

from zentinel_agent_sdk import Decision, Request
from zentinel_agent_sdk.v2 import AgentCapabilities, AgentRunnerV2, AgentV2


class HelloAgent(AgentV2):
    @property
    def name(self) -> str:
        return "hello"

    def capabilities(self) -> AgentCapabilities:
        return AgentCapabilities("hello", "Hello agent", "0.1.0")

    async def on_request(self, request: Request) -> Decision:
        return Decision.allow().add_request_header("X-Hello", "from-agent")


if __name__ == "__main__":
    socket_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/hello.sock"
    asyncio.run(AgentRunnerV2(HelloAgent()).with_uds(socket_path).run())
