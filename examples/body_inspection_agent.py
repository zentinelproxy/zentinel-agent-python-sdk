#!/usr/bin/env python3
"""Body inspection Sentinel agent example.

This example demonstrates an agent that inspects request and response bodies:
- Validates JSON request bodies
- Scans for sensitive data patterns
- Modifies response headers based on content
"""

import re
from typing import Any

from sentinel_agent_sdk import Agent, Decision, Request, Response, run_agent


class BodyInspectionAgent(Agent):
    """An agent that inspects request and response bodies."""

    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),  # Social Security Number
        (r"\b\d{16}\b", "CREDIT_CARD"),  # Credit card (simplified)
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL"),
    ]

    @property
    def name(self) -> str:
        return "body-inspection-agent"

    async def on_request(self, request: Request) -> Decision:
        """Process request headers."""
        # For POST/PUT with JSON, we'll inspect the body
        if request.is_post() or request.is_put():
            if request.is_json():
                # Request body inspection in on_request_body
                return Decision.allow().with_tag("needs_body_inspection")

        return Decision.allow()

    async def on_request_body(self, request: Request) -> Decision:
        """Inspect request body for sensitive data."""
        body_str = request.body_str

        # Check for sensitive data patterns
        detected: list[str] = []
        for pattern, name in self.SENSITIVE_PATTERNS:
            if re.search(pattern, body_str):
                detected.append(name)

        if detected:
            return (
                Decision.deny()
                .with_body("Request contains sensitive data")
                .with_tags(["sensitive_data", "pii"])
                .with_metadata("detected_types", detected)
                .with_confidence(0.9)
            )

        # Validate JSON structure if applicable
        if request.is_json():
            try:
                data: Any = request.body_json()

                # Example validation: check for required fields
                if isinstance(data, dict):
                    # Add validation headers
                    return Decision.allow().add_request_header(
                        "X-Body-Validated", "true"
                    )
            except Exception as e:
                return (
                    Decision.block(400)
                    .with_body(f"Invalid JSON: {e}")
                    .with_tag("invalid_json")
                )

        return Decision.allow()

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Process response headers."""
        # Add content type info
        if response.is_json():
            return Decision.allow().add_response_header("X-Content-Type-Validated", "json")
        elif response.is_html():
            return Decision.allow().add_response_header("X-Content-Type-Validated", "html")

        return Decision.allow()

    async def on_response_body(self, request: Request, response: Response) -> Decision:
        """Inspect response body."""
        body_str = response.body_str

        # Check for sensitive data in response
        detected: list[str] = []
        for pattern, name in self.SENSITIVE_PATTERNS:
            if re.search(pattern, body_str):
                detected.append(name)

        if detected:
            # Log but don't block - response already sent
            return (
                Decision.allow()
                .with_tags(["sensitive_data_response", "pii"])
                .with_metadata("detected_types", detected)
                .with_reason_code("SENSITIVE_DATA_IN_RESPONSE")
            )

        return Decision.allow()


if __name__ == "__main__":
    run_agent(BodyInspectionAgent())
