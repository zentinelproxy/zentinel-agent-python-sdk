"""Core Agent trait and base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from sentinel_agent_sdk.decision import Decision
from sentinel_agent_sdk.request import Request
from sentinel_agent_sdk.response import Response

T = TypeVar("T")


class Agent(ABC):
    """Base class for Sentinel agents.

    Implement this class to create a custom agent that can process
    HTTP requests and responses in the Sentinel proxy pipeline.

    Example:
        class MyAgent(Agent):
            @property
            def name(self) -> str:
                return "my-agent"

            async def on_request(self, request: Request) -> Decision:
                if request.path_starts_with("/blocked"):
                    return Decision.deny().with_body("Blocked")
                return Decision.allow()
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the agent name for logging.

        Returns:
            The agent identifier string.
        """
        ...

    async def on_configure(self, config: dict[str, Any]) -> None:
        """Handle configuration from the proxy.

        Called once when the agent connects to the proxy.
        Override to validate and store configuration.

        Args:
            config: Configuration dictionary from proxy.

        Raises:
            ValueError: If configuration is invalid.
        """
        pass

    async def on_request(self, request: Request) -> Decision:
        """Process incoming request headers.

        Called when request headers are received from the client.
        Override to implement request inspection and filtering.

        Args:
            request: The incoming request.

        Returns:
            A Decision indicating how to handle the request.
        """
        return Decision.allow()

    async def on_request_body(self, request: Request) -> Decision:
        """Process request body.

        Called when request body is available (if body inspection enabled).
        Override to inspect or modify request body content.

        Args:
            request: The request with body populated.

        Returns:
            A Decision indicating how to handle the request.
        """
        return Decision.allow()

    async def on_response(self, request: Request, response: Response) -> Decision:
        """Process response headers from upstream.

        Called when response headers are received from the upstream server.
        Override to inspect or modify response headers.

        Args:
            request: The original request.
            response: The response from upstream.

        Returns:
            A Decision indicating how to handle the response.
        """
        return Decision.allow()

    async def on_response_body(self, request: Request, response: Response) -> Decision:
        """Process response body.

        Called when response body is available (if body inspection enabled).
        Override to inspect or modify response body content.

        Args:
            request: The original request.
            response: The response with body populated.

        Returns:
            A Decision indicating how to handle the response.
        """
        return Decision.allow()

    async def on_request_complete(
        self,
        request: Request,
        status: int,
        duration_ms: int,
    ) -> None:
        """Called when request processing is complete.

        Override for logging, metrics, or cleanup.

        Args:
            request: The completed request.
            status: The final response status code.
            duration_ms: The request duration in milliseconds.
        """
        pass


class ConfigurableAgent(Agent, Generic[T]):
    """Agent with typed configuration support.

    Extend this class when your agent needs structured configuration.
    The configuration type T should be a dataclass or Pydantic model.

    Example:
        @dataclass
        class MyConfig:
            rate_limit: int = 100
            enabled: bool = True

        class MyAgent(ConfigurableAgent[MyConfig]):
            def __init__(self):
                super().__init__(MyConfig())

            @property
            def name(self) -> str:
                return "my-agent"

            async def on_request(self, request: Request) -> Decision:
                if not self.config.enabled:
                    return Decision.allow()
                # Use self.config.rate_limit...
                return Decision.allow()
    """

    def __init__(self, default_config: T) -> None:
        """Initialize with default configuration.

        Args:
            default_config: The default configuration instance.
        """
        self._config = default_config

    @property
    def config(self) -> T:
        """Get the current configuration.

        Returns:
            The current configuration instance.
        """
        return self._config

    def parse_config(self, config_dict: dict[str, Any]) -> T:
        """Parse configuration dictionary into typed config.

        Override this method to customize config parsing.
        Default implementation works with dataclasses.

        Args:
            config_dict: The configuration dictionary.

        Returns:
            The parsed configuration instance.
        """
        import dataclasses

        if dataclasses.is_dataclass(self._config):
            config_type = type(self._config)
            return config_type(**config_dict)  # type: ignore
        # For Pydantic models
        config_type = type(self._config)
        if hasattr(config_type, "model_validate"):
            return config_type.model_validate(config_dict)  # type: ignore
        raise TypeError(f"Cannot parse config for type {config_type}")

    async def on_configure(self, config: dict[str, Any]) -> None:
        """Handle configuration from the proxy.

        Parses the config dict and stores it. Override parse_config
        to customize parsing behavior.

        Args:
            config: Configuration dictionary from proxy.
        """
        self._config = self.parse_config(config)
        await self.on_config_applied(self._config)

    async def on_config_applied(self, config: T) -> None:
        """Called after configuration is applied.

        Override for any post-configuration setup.

        Args:
            config: The newly applied configuration.
        """
        pass
