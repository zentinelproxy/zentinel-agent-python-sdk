"""Zentinel Agent SDK for Python.

A Python SDK for building agents that integrate with Zentinel reverse proxy.

All agents use v2 protocol with gRPC + UDS support.

    from zentinel_agent_sdk import Decision, Request
    from zentinel_agent_sdk.v2 import AgentV2, AgentCapabilities, AgentRunnerV2
"""

from zentinel_agent_sdk.agent import Agent, ConfigurableAgent
from zentinel_agent_sdk.decision import Decision, decisions
from zentinel_agent_sdk.protocol import (
    PROTOCOL_VERSION,
    DetectionSeverity,
    GuardrailDetection,
    GuardrailInspectEvent,
    GuardrailInspectionType,
    GuardrailResponse,
    TextSpan,
)
from zentinel_agent_sdk.request import Request
from zentinel_agent_sdk.response import Response
from zentinel_agent_sdk.runner import AgentRunner, RunnerConfig, run_agent

# Import v2 module for convenient access
from zentinel_agent_sdk import v2

__version__ = "0.2.0"
__all__ = [
    # Agent
    "Agent",
    "ConfigurableAgent",
    "AgentRunner",
    "RunnerConfig",
    "run_agent",
    # Common types
    "Request",
    "Response",
    "Decision",
    "decisions",
    "PROTOCOL_VERSION",
    # Guardrail types
    "GuardrailInspectEvent",
    "GuardrailInspectionType",
    "GuardrailResponse",
    "GuardrailDetection",
    "DetectionSeverity",
    "TextSpan",
    # v2 module
    "v2",
]
