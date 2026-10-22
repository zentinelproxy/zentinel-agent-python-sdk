"""The SDK against a real Zentinel, through the shared conformance harness.

The harness (`sdk-conformance/run.py` in zentinelproxy/zentinel) starts a
`zentinel` binary in front of an echo upstream and checks over HTTP that the
agents in `examples/` speak agent protocol v2: handshake, configure, header
mutations, block, body inspection, reconnect. CI runs it through the
harness's GitHub Action; this test runs the same thing locally:

    ZENTINEL_BIN=/path/to/zentinel \\
    ZENTINEL_CONFORMANCE_HARNESS=/path/to/zentinel/sdk-conformance/run.py \\
    python -m pytest tests/integration -v

Both variables are required; without them the tests are skipped.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = os.environ.get("ZENTINEL_CONFORMANCE_HARNESS")
ZENTINEL = os.environ.get("ZENTINEL_BIN")

pytestmark = pytest.mark.skipif(
    not (HARNESS and ZENTINEL),
    reason="set ZENTINEL_BIN and ZENTINEL_CONFORMANCE_HARNESS to run against a real proxy",
)


def _example(name: str) -> str:
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(ROOT / 'examples' / name))}"


def _harness(*args: str) -> subprocess.CompletedProcess[str]:
    assert HARNESS and ZENTINEL
    return subprocess.run(
        [sys.executable, HARNESS, "--zentinel-bin", ZENTINEL, *args],
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_conformance_agent_uds_and_grpc() -> None:
    result = _harness(
        "--agent-cmd",
        _example("conformance_agent.py") + " --socket {socket}",
        "--grpc-agent-cmd",
        _example("conformance_agent.py") + " --grpc {grpc}",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_readme_hello_agent() -> None:
    result = _harness("--profile", "hello", "--agent-cmd", _example("hello_agent.py") + " {socket}")
    assert result.returncode == 0, result.stdout + result.stderr
