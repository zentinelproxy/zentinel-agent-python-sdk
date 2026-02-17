#!/usr/bin/env python3
"""Guardrail agent example for AI content safety.

This example demonstrates a guardrail agent that:
- Detects prompt injection attempts in user input
- Detects PII (emails, phone numbers, SSN patterns)
- Returns structured detection results with confidence scores
"""

import re
from zentinel_agent_sdk import (
    Agent,
    Decision,
    Request,
    run_agent,
    GuardrailInspectEvent,
    GuardrailResponse,
    GuardrailDetection,
    DetectionSeverity,
    GuardrailInspectionType,
)


class GuardrailAgent(Agent):
    """An agent that inspects content for prompt injection and PII."""

    # Prompt injection patterns
    INJECTION_PATTERNS = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", "ignore_instructions"),
        (r"disregard\s+(all\s+)?(previous|prior|above)", "disregard_previous"),
        (r"you\s+are\s+now\s+(a|an|in)\s+", "role_switch"),
        (r"pretend\s+(you('re|are)|to\s+be)", "pretend_role"),
        (r"system\s*:\s*", "system_prompt_inject"),
        (r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", "llama_format_inject"),
        (r"<\|im_start\|>|<\|im_end\|>", "chatml_format_inject"),
    ]

    # PII patterns
    PII_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email", "Email address"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone", "Phone number"),
        (r"\b\d{3}[-]?\d{2}[-]?\d{4}\b", "ssn", "Social Security Number"),
        (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "credit_card", "Credit card number"),
    ]

    @property
    def name(self) -> str:
        return "guardrail-agent"

    async def on_request(self, request: Request) -> Decision:
        """Allow all requests - guardrail inspection happens via on_guardrail_inspect."""
        return Decision.allow()

    async def on_guardrail_inspect(self, event: GuardrailInspectEvent) -> GuardrailResponse:
        """Inspect content for prompt injection or PII based on inspection type."""
        if event.inspection_type == GuardrailInspectionType.PROMPT_INJECTION:
            return self._detect_prompt_injection(event.content)
        elif event.inspection_type == GuardrailInspectionType.PII_DETECTION:
            return self._detect_pii(event.content)
        else:
            return GuardrailResponse.clean()

    def _detect_prompt_injection(self, content: str) -> GuardrailResponse:
        """Detect prompt injection attempts in content."""
        response = GuardrailResponse.clean()
        content_lower = content.lower()

        for pattern, category in self.INJECTION_PATTERNS:
            match = re.search(pattern, content_lower)
            if match:
                detection = GuardrailDetection(
                    category=f"prompt_injection.{category}",
                    description=f"Potential prompt injection detected: {category.replace('_', ' ')}",
                    severity=DetectionSeverity.HIGH,
                    confidence=0.85,
                )
                # Add span if we can find it
                detection = detection.with_span(match.start(), match.end())
                response = response.add_detection(detection)

        return response

    def _detect_pii(self, content: str) -> GuardrailResponse:
        """Detect PII in content and optionally redact it."""
        response = GuardrailResponse.clean()
        redacted = content

        for pattern, category, description in self.PII_PATTERNS:
            for match in re.finditer(pattern, content):
                detection = GuardrailDetection(
                    category=f"pii.{category}",
                    description=f"{description} detected",
                    severity=DetectionSeverity.MEDIUM,
                    confidence=0.95,
                )
                detection = detection.with_span(match.start(), match.end())
                response = response.add_detection(detection)

                # Redact the PII
                redacted = redacted.replace(match.group(), f"[REDACTED_{category.upper()}]")

        if response.detected:
            response = response.with_redacted_content(redacted)

        return response


if __name__ == "__main__":
    run_agent(GuardrailAgent())
