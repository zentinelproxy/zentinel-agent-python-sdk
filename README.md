<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Python agent SDK</h3>

<p align="center">Write Zentinel agents in Python, speaking agent protocol v2 over a Unix socket or gRPC.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-python-sdk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-python-sdk/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-f68d31?style=flat&labelColor=1f161e&logo=python&logoColor=white">
</p>

<p align="center">
  <a href="https://docs.zentinelproxy.io/agents/v2/">Agent protocol</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The SDK gives you an asyncio `Agent` base class with one coroutine per event, a
`Decision` builder, typed configuration, and in `zentinel_agent_sdk.v2` a runner
with Unix socket and gRPC transports and health reporting. It is not on PyPI;
install it from GitHub.

> **Status (checked on 2026-10-22): agents built with this SDK work with Zentinel over agent protocol v2, on both the Unix socket and gRPC.**
> CI runs them behind a real `zentinel` binary through the shared
> [conformance harness](https://github.com/zentinelproxy/zentinel/tree/sdk/conformance-harness/sdk-conformance):
> handshake, configuration, request and response header changes, blocking,
> request-body inspection, and reconnecting after the agent restarts all pass.
> Delivery of the agent's `config { }` block to `on_configure` needs a Zentinel
> with zentinel#603, which is on `main` but not in a release yet (26.10_7 and
> earlier never send it). Version 0.2.0 and earlier spoke the v1 framing and
> could not connect at all (zentinel#600).

## Quick start

With the SDK installed (see [Install](#install)), create `hello_agent.py`:

```python
import asyncio

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
    asyncio.run(AgentRunnerV2(HelloAgent()).with_uds("/tmp/hello.sock").run())
```

Run it with `python hello_agent.py`. It listens on `/tmp/hello.sock`.

Then point Zentinel at the socket. This assumes your config already defines a
listener and an upstream named `backend`:

```kdl
agents {
    agent "hello" type="custom" {
        unix-socket "/tmp/hello.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "hello" {
        type "agent"
        agent "hello"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "hello"
    }
}
```

Check the file with `zentinel test -c zentinel.kdl` and start Zentinel. Every
request on the route then reaches `backend` with `X-Hello: from-agent`.
`failure-mode "closed"` on the filter turns an unreachable agent into a 503
instead of letting requests through unprocessed, so a wiring mistake shows up
on the first request.

The same agent is [`examples/hello_agent.py`](examples/hello_agent.py), and
CI runs it through the conformance harness. For gRPC, use
`.with_grpc("127.0.0.1:50051")` and `grpc "http://127.0.0.1:50051"` in the
agent block instead.

## Install

```bash
pip install "zentinel-agent-sdk @ git+https://github.com/zentinelproxy/zentinel-agent-python-sdk"
```

Python 3.10 or later (`requires-python`). The package is **not on PyPI**:
`pip install zentinel-agent-sdk` finds nothing. (The crates.io package of the
same name is the Rust SDK.)

## API overview

- **`Agent`**: `name`, `on_request`, `on_request_body`, `on_response`,
  `on_response_body`, `on_request_complete`, `on_configure`,
  `on_guardrail_inspect`. All hooks default to allow.
- **`ConfigurableAgent[T]`**: typed configuration from the agent's `config` block.
- **`v2.AgentV2`**: adds `capabilities()` (required), health status and
  metrics; `v2.AgentRunnerV2` with `with_uds`, `with_grpc`, `with_both`;
  `v2.run_agent_v2(agent)` reads `--socket`, `--grpc` (either or both),
  `--log-level`, `--json-logs`.
- **`run_agent(agent)` / `AgentRunner`**: the same v2 runner for a plain
  `Agent`; `--socket` and optionally `--grpc`.
- **Configuration**: `on_configure` receives the agent's `config { }` block on
  every connection the proxy opens (each pooled one and every reconnect), so it
  must be idempotent. Raising rejects the configuration, and the proxy then
  does not use that connection.
- **`Request` / `Response`**: header, path, query, client IP and body accessors.
- **`Decision`**: `allow()`, `deny()`, `unauthorized()`, `rate_limited()`,
  `block(status)`, `redirect(url)`, `challenge(..)`, then chain
  `add_request_header`, `remove_request_header`, `add_response_header`,
  `with_body`, `with_json_body`, `with_tag`, `with_rule_id`, `with_confidence`,
  `with_metadata`, `with_routing_metadata`, body mutations.

Examples are in [`examples/`](examples/).

## Development

```bash
mise install                      # Python 3.12 and uv
python -m pip install -e ".[dev]"
python -m pytest tests
ruff check src tests
mypy src
```

`tests/integration` runs the agents in `examples/` against a real proxy
through the conformance harness, and is skipped unless both `ZENTINEL_BIN` (a
`zentinel` binary) and `ZENTINEL_CONFORMANCE_HARNESS` (the harness's
`sdk-conformance/run.py`) are set.

CI runs the tests on Python 3.10, 3.11 and 3.12, and the conformance harness
against Zentinel built from `main`. The generated gRPC code in
`src/zentinel_agent_sdk/v2/proto/` is committed; see its `__init__.py` to
regenerate it.

## Related

- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Guides in this repository](docs/index.md): getting started, API, configuration, examples
- [Other SDKs](https://github.com/zentinelproxy?q=sdk)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
