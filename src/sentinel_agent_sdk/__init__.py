"""Sentinel Agent SDK for Python.

A Python SDK for building agents that integrate with Sentinel reverse proxy.
"""

from sentinel_agent_sdk.agent import Agent, ConfigurableAgent
from sentinel_agent_sdk.decision import Decision, decisions
from sentinel_agent_sdk.protocol import (
    PROTOCOL_VERSION,
    DetectionSeverity,
    GuardrailDetection,
    GuardrailInspectEvent,
    GuardrailInspectionType,
    GuardrailResponse,
    TextSpan,
)
from sentinel_agent_sdk.request import Request
from sentinel_agent_sdk.response import Response
from sentinel_agent_sdk.runner import AgentRunner, RunnerConfig, run_agent

__version__ = "0.1.0"
__all__ = [
    "Agent",
    "ConfigurableAgent",
    "AgentRunner",
    "RunnerConfig",
    "run_agent",
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
]
