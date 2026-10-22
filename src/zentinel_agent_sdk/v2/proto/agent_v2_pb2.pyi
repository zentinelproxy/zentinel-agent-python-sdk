from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVENT_TYPE_UNSPECIFIED: _ClassVar[EventType]
    EVENT_TYPE_REQUEST_HEADERS: _ClassVar[EventType]
    EVENT_TYPE_REQUEST_BODY_CHUNK: _ClassVar[EventType]
    EVENT_TYPE_RESPONSE_HEADERS: _ClassVar[EventType]
    EVENT_TYPE_RESPONSE_BODY_CHUNK: _ClassVar[EventType]
    EVENT_TYPE_REQUEST_COMPLETE: _ClassVar[EventType]
    EVENT_TYPE_WEBSOCKET_FRAME: _ClassVar[EventType]
    EVENT_TYPE_GUARDRAIL_INSPECT: _ClassVar[EventType]
    EVENT_TYPE_CONFIGURE: _ClassVar[EventType]

class HealthState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HEALTH_STATE_UNSPECIFIED: _ClassVar[HealthState]
    HEALTH_STATE_HEALTHY: _ClassVar[HealthState]
    HEALTH_STATE_DEGRADED: _ClassVar[HealthState]
    HEALTH_STATE_DRAINING: _ClassVar[HealthState]
    HEALTH_STATE_UNHEALTHY: _ClassVar[HealthState]

class FlowAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLOW_ACTION_UNSPECIFIED: _ClassVar[FlowAction]
    FLOW_ACTION_PAUSE: _ClassVar[FlowAction]
    FLOW_ACTION_RESUME: _ClassVar[FlowAction]
    FLOW_ACTION_UPDATE_CAPACITY: _ClassVar[FlowAction]

class CancelReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CANCEL_REASON_UNSPECIFIED: _ClassVar[CancelReason]
    CANCEL_REASON_CLIENT_DISCONNECT: _ClassVar[CancelReason]
    CANCEL_REASON_TIMEOUT: _ClassVar[CancelReason]
    CANCEL_REASON_BLOCKED_BY_AGENT: _ClassVar[CancelReason]
    CANCEL_REASON_UPSTREAM_ERROR: _ClassVar[CancelReason]
    CANCEL_REASON_PROXY_SHUTDOWN: _ClassVar[CancelReason]
    CANCEL_REASON_MANUAL: _ClassVar[CancelReason]

class LogLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LOG_LEVEL_UNSPECIFIED: _ClassVar[LogLevel]
    LOG_LEVEL_DEBUG: _ClassVar[LogLevel]
    LOG_LEVEL_INFO: _ClassVar[LogLevel]
    LOG_LEVEL_WARN: _ClassVar[LogLevel]
    LOG_LEVEL_ERROR: _ClassVar[LogLevel]

class GuardrailContentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARDRAIL_CONTENT_TYPE_UNSPECIFIED: _ClassVar[GuardrailContentType]
    GUARDRAIL_CONTENT_TYPE_PROMPT: _ClassVar[GuardrailContentType]
    GUARDRAIL_CONTENT_TYPE_RESPONSE: _ClassVar[GuardrailContentType]
    GUARDRAIL_CONTENT_TYPE_SYSTEM: _ClassVar[GuardrailContentType]
    GUARDRAIL_CONTENT_TYPE_TOOL_CALL: _ClassVar[GuardrailContentType]
    GUARDRAIL_CONTENT_TYPE_TOOL_RESULT: _ClassVar[GuardrailContentType]
EVENT_TYPE_UNSPECIFIED: EventType
EVENT_TYPE_REQUEST_HEADERS: EventType
EVENT_TYPE_REQUEST_BODY_CHUNK: EventType
EVENT_TYPE_RESPONSE_HEADERS: EventType
EVENT_TYPE_RESPONSE_BODY_CHUNK: EventType
EVENT_TYPE_REQUEST_COMPLETE: EventType
EVENT_TYPE_WEBSOCKET_FRAME: EventType
EVENT_TYPE_GUARDRAIL_INSPECT: EventType
EVENT_TYPE_CONFIGURE: EventType
HEALTH_STATE_UNSPECIFIED: HealthState
HEALTH_STATE_HEALTHY: HealthState
HEALTH_STATE_DEGRADED: HealthState
HEALTH_STATE_DRAINING: HealthState
HEALTH_STATE_UNHEALTHY: HealthState
FLOW_ACTION_UNSPECIFIED: FlowAction
FLOW_ACTION_PAUSE: FlowAction
FLOW_ACTION_RESUME: FlowAction
FLOW_ACTION_UPDATE_CAPACITY: FlowAction
CANCEL_REASON_UNSPECIFIED: CancelReason
CANCEL_REASON_CLIENT_DISCONNECT: CancelReason
CANCEL_REASON_TIMEOUT: CancelReason
CANCEL_REASON_BLOCKED_BY_AGENT: CancelReason
CANCEL_REASON_UPSTREAM_ERROR: CancelReason
CANCEL_REASON_PROXY_SHUTDOWN: CancelReason
CANCEL_REASON_MANUAL: CancelReason
LOG_LEVEL_UNSPECIFIED: LogLevel
LOG_LEVEL_DEBUG: LogLevel
LOG_LEVEL_INFO: LogLevel
LOG_LEVEL_WARN: LogLevel
LOG_LEVEL_ERROR: LogLevel
GUARDRAIL_CONTENT_TYPE_UNSPECIFIED: GuardrailContentType
GUARDRAIL_CONTENT_TYPE_PROMPT: GuardrailContentType
GUARDRAIL_CONTENT_TYPE_RESPONSE: GuardrailContentType
GUARDRAIL_CONTENT_TYPE_SYSTEM: GuardrailContentType
GUARDRAIL_CONTENT_TYPE_TOOL_CALL: GuardrailContentType
GUARDRAIL_CONTENT_TYPE_TOOL_RESULT: GuardrailContentType

class AgentCapabilities(_message.Message):
    __slots__ = ("protocol_version", "agent_id", "name", "version", "supported_events", "features", "limits", "health_config")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_EVENTS_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    HEALTH_CONFIG_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    agent_id: str
    name: str
    version: str
    supported_events: _containers.RepeatedScalarFieldContainer[int]
    features: AgentFeatures
    limits: AgentLimits
    health_config: HealthConfig
    def __init__(self, protocol_version: _Optional[int] = ..., agent_id: _Optional[str] = ..., name: _Optional[str] = ..., version: _Optional[str] = ..., supported_events: _Optional[_Iterable[int]] = ..., features: _Optional[_Union[AgentFeatures, _Mapping]] = ..., limits: _Optional[_Union[AgentLimits, _Mapping]] = ..., health_config: _Optional[_Union[HealthConfig, _Mapping]] = ...) -> None: ...

class AgentFeatures(_message.Message):
    __slots__ = ("streaming_body", "websocket", "guardrails", "config_push", "metrics_export", "concurrent_requests", "cancellation", "flow_control", "health_reporting")
    STREAMING_BODY_FIELD_NUMBER: _ClassVar[int]
    WEBSOCKET_FIELD_NUMBER: _ClassVar[int]
    GUARDRAILS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_PUSH_FIELD_NUMBER: _ClassVar[int]
    METRICS_EXPORT_FIELD_NUMBER: _ClassVar[int]
    CONCURRENT_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    FLOW_CONTROL_FIELD_NUMBER: _ClassVar[int]
    HEALTH_REPORTING_FIELD_NUMBER: _ClassVar[int]
    streaming_body: bool
    websocket: bool
    guardrails: bool
    config_push: bool
    metrics_export: bool
    concurrent_requests: int
    cancellation: bool
    flow_control: bool
    health_reporting: bool
    def __init__(self, streaming_body: bool = ..., websocket: bool = ..., guardrails: bool = ..., config_push: bool = ..., metrics_export: bool = ..., concurrent_requests: _Optional[int] = ..., cancellation: bool = ..., flow_control: bool = ..., health_reporting: bool = ...) -> None: ...

class AgentLimits(_message.Message):
    __slots__ = ("max_body_size", "max_concurrency", "preferred_chunk_size", "max_memory", "max_processing_time_ms")
    MAX_BODY_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENCY_FIELD_NUMBER: _ClassVar[int]
    PREFERRED_CHUNK_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAX_MEMORY_FIELD_NUMBER: _ClassVar[int]
    MAX_PROCESSING_TIME_MS_FIELD_NUMBER: _ClassVar[int]
    max_body_size: int
    max_concurrency: int
    preferred_chunk_size: int
    max_memory: int
    max_processing_time_ms: int
    def __init__(self, max_body_size: _Optional[int] = ..., max_concurrency: _Optional[int] = ..., preferred_chunk_size: _Optional[int] = ..., max_memory: _Optional[int] = ..., max_processing_time_ms: _Optional[int] = ...) -> None: ...

class HealthConfig(_message.Message):
    __slots__ = ("report_interval_ms", "include_load_metrics", "include_resource_metrics")
    REPORT_INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_LOAD_METRICS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_RESOURCE_METRICS_FIELD_NUMBER: _ClassVar[int]
    report_interval_ms: int
    include_load_metrics: bool
    include_resource_metrics: bool
    def __init__(self, report_interval_ms: _Optional[int] = ..., include_load_metrics: bool = ..., include_resource_metrics: bool = ...) -> None: ...

class HandshakeRequest(_message.Message):
    __slots__ = ("supported_versions", "proxy_id", "proxy_version", "config_json")
    SUPPORTED_VERSIONS_FIELD_NUMBER: _ClassVar[int]
    PROXY_ID_FIELD_NUMBER: _ClassVar[int]
    PROXY_VERSION_FIELD_NUMBER: _ClassVar[int]
    CONFIG_JSON_FIELD_NUMBER: _ClassVar[int]
    supported_versions: _containers.RepeatedScalarFieldContainer[int]
    proxy_id: str
    proxy_version: str
    config_json: str
    def __init__(self, supported_versions: _Optional[_Iterable[int]] = ..., proxy_id: _Optional[str] = ..., proxy_version: _Optional[str] = ..., config_json: _Optional[str] = ...) -> None: ...

class HandshakeResponse(_message.Message):
    __slots__ = ("protocol_version", "capabilities", "success", "error")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    capabilities: AgentCapabilities
    success: bool
    error: str
    def __init__(self, protocol_version: _Optional[int] = ..., capabilities: _Optional[_Union[AgentCapabilities, _Mapping]] = ..., success: bool = ..., error: _Optional[str] = ...) -> None: ...

class HealthStatus(_message.Message):
    __slots__ = ("agent_id", "state", "message", "load", "resources", "valid_until_ms", "timestamp_ms", "disabled_features", "timeout_multiplier", "drain_eta_ms", "unhealthy_reason", "recoverable")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    LOAD_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_MS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FEATURES_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MULTIPLIER_FIELD_NUMBER: _ClassVar[int]
    DRAIN_ETA_MS_FIELD_NUMBER: _ClassVar[int]
    UNHEALTHY_REASON_FIELD_NUMBER: _ClassVar[int]
    RECOVERABLE_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    state: int
    message: str
    load: LoadMetrics
    resources: ResourceMetrics
    valid_until_ms: int
    timestamp_ms: int
    disabled_features: _containers.RepeatedScalarFieldContainer[str]
    timeout_multiplier: float
    drain_eta_ms: int
    unhealthy_reason: str
    recoverable: bool
    def __init__(self, agent_id: _Optional[str] = ..., state: _Optional[int] = ..., message: _Optional[str] = ..., load: _Optional[_Union[LoadMetrics, _Mapping]] = ..., resources: _Optional[_Union[ResourceMetrics, _Mapping]] = ..., valid_until_ms: _Optional[int] = ..., timestamp_ms: _Optional[int] = ..., disabled_features: _Optional[_Iterable[str]] = ..., timeout_multiplier: _Optional[float] = ..., drain_eta_ms: _Optional[int] = ..., unhealthy_reason: _Optional[str] = ..., recoverable: bool = ...) -> None: ...

class LoadMetrics(_message.Message):
    __slots__ = ("in_flight", "queue_depth", "avg_latency_ms", "p50_latency_ms", "p95_latency_ms", "p99_latency_ms", "requests_processed", "requests_rejected", "requests_timed_out")
    IN_FLIGHT_FIELD_NUMBER: _ClassVar[int]
    QUEUE_DEPTH_FIELD_NUMBER: _ClassVar[int]
    AVG_LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    P50_LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    P95_LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    P99_LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_PROCESSED_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_REJECTED_FIELD_NUMBER: _ClassVar[int]
    REQUESTS_TIMED_OUT_FIELD_NUMBER: _ClassVar[int]
    in_flight: int
    queue_depth: int
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    requests_processed: int
    requests_rejected: int
    requests_timed_out: int
    def __init__(self, in_flight: _Optional[int] = ..., queue_depth: _Optional[int] = ..., avg_latency_ms: _Optional[float] = ..., p50_latency_ms: _Optional[float] = ..., p95_latency_ms: _Optional[float] = ..., p99_latency_ms: _Optional[float] = ..., requests_processed: _Optional[int] = ..., requests_rejected: _Optional[int] = ..., requests_timed_out: _Optional[int] = ...) -> None: ...

class ResourceMetrics(_message.Message):
    __slots__ = ("cpu_percent", "memory_bytes", "memory_limit", "active_threads", "open_fds", "fd_limit", "connections")
    CPU_PERCENT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_LIMIT_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_THREADS_FIELD_NUMBER: _ClassVar[int]
    OPEN_FDS_FIELD_NUMBER: _ClassVar[int]
    FD_LIMIT_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    cpu_percent: float
    memory_bytes: int
    memory_limit: int
    active_threads: int
    open_fds: int
    fd_limit: int
    connections: int
    def __init__(self, cpu_percent: _Optional[float] = ..., memory_bytes: _Optional[int] = ..., memory_limit: _Optional[int] = ..., active_threads: _Optional[int] = ..., open_fds: _Optional[int] = ..., fd_limit: _Optional[int] = ..., connections: _Optional[int] = ...) -> None: ...

class CancelRequest(_message.Message):
    __slots__ = ("correlation_id", "reason", "timestamp_ms", "blocking_agent_id", "manual_reason")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    BLOCKING_AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    MANUAL_REASON_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    reason: int
    timestamp_ms: int
    blocking_agent_id: str
    manual_reason: str
    def __init__(self, correlation_id: _Optional[str] = ..., reason: _Optional[int] = ..., timestamp_ms: _Optional[int] = ..., blocking_agent_id: _Optional[str] = ..., manual_reason: _Optional[str] = ...) -> None: ...

class ConfigUpdateRequest(_message.Message):
    __slots__ = ("request_id", "timestamp_ms", "request_reload", "rule_update", "list_update", "restart_required", "config_error")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_RELOAD_FIELD_NUMBER: _ClassVar[int]
    RULE_UPDATE_FIELD_NUMBER: _ClassVar[int]
    LIST_UPDATE_FIELD_NUMBER: _ClassVar[int]
    RESTART_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    CONFIG_ERROR_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    timestamp_ms: int
    request_reload: RequestReload
    rule_update: RuleUpdate
    list_update: ListUpdate
    restart_required: RestartRequired
    config_error: ConfigError
    def __init__(self, request_id: _Optional[str] = ..., timestamp_ms: _Optional[int] = ..., request_reload: _Optional[_Union[RequestReload, _Mapping]] = ..., rule_update: _Optional[_Union[RuleUpdate, _Mapping]] = ..., list_update: _Optional[_Union[ListUpdate, _Mapping]] = ..., restart_required: _Optional[_Union[RestartRequired, _Mapping]] = ..., config_error: _Optional[_Union[ConfigError, _Mapping]] = ...) -> None: ...

class RequestReload(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RuleUpdate(_message.Message):
    __slots__ = ("rule_set", "rules", "remove_rules")
    RULE_SET_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    REMOVE_RULES_FIELD_NUMBER: _ClassVar[int]
    rule_set: str
    rules: _containers.RepeatedCompositeFieldContainer[RuleDefinition]
    remove_rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, rule_set: _Optional[str] = ..., rules: _Optional[_Iterable[_Union[RuleDefinition, _Mapping]]] = ..., remove_rules: _Optional[_Iterable[str]] = ...) -> None: ...

class ListUpdate(_message.Message):
    __slots__ = ("list_id", "add", "remove")
    LIST_ID_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    list_id: str
    add: _containers.RepeatedScalarFieldContainer[str]
    remove: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, list_id: _Optional[str] = ..., add: _Optional[_Iterable[str]] = ..., remove: _Optional[_Iterable[str]] = ...) -> None: ...

class RestartRequired(_message.Message):
    __slots__ = ("reason", "grace_period_ms")
    REASON_FIELD_NUMBER: _ClassVar[int]
    GRACE_PERIOD_MS_FIELD_NUMBER: _ClassVar[int]
    reason: str
    grace_period_ms: int
    def __init__(self, reason: _Optional[str] = ..., grace_period_ms: _Optional[int] = ...) -> None: ...

class ConfigError(_message.Message):
    __slots__ = ("error", "field")
    ERROR_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    error: str
    field: str
    def __init__(self, error: _Optional[str] = ..., field: _Optional[str] = ...) -> None: ...

class RuleDefinition(_message.Message):
    __slots__ = ("id", "priority", "definition_json", "enabled", "description", "tags")
    ID_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_JSON_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    id: str
    priority: int
    definition_json: str
    enabled: bool
    description: str
    tags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, id: _Optional[str] = ..., priority: _Optional[int] = ..., definition_json: _Optional[str] = ..., enabled: bool = ..., description: _Optional[str] = ..., tags: _Optional[_Iterable[str]] = ...) -> None: ...

class ConfigUpdateResponse(_message.Message):
    __slots__ = ("request_id", "accepted", "error", "timestamp_ms")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    accepted: bool
    error: str
    timestamp_ms: int
    def __init__(self, request_id: _Optional[str] = ..., accepted: bool = ..., error: _Optional[str] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class ShutdownRequest(_message.Message):
    __slots__ = ("reason", "grace_period_ms", "timestamp_ms")
    class Reason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REASON_UNSPECIFIED: _ClassVar[ShutdownRequest.Reason]
        REASON_GRACEFUL: _ClassVar[ShutdownRequest.Reason]
        REASON_IMMEDIATE: _ClassVar[ShutdownRequest.Reason]
        REASON_CONFIG_RELOAD: _ClassVar[ShutdownRequest.Reason]
        REASON_UPGRADE: _ClassVar[ShutdownRequest.Reason]
    REASON_UNSPECIFIED: ShutdownRequest.Reason
    REASON_GRACEFUL: ShutdownRequest.Reason
    REASON_IMMEDIATE: ShutdownRequest.Reason
    REASON_CONFIG_RELOAD: ShutdownRequest.Reason
    REASON_UPGRADE: ShutdownRequest.Reason
    REASON_FIELD_NUMBER: _ClassVar[int]
    GRACE_PERIOD_MS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    reason: int
    grace_period_ms: int
    timestamp_ms: int
    def __init__(self, reason: _Optional[int] = ..., grace_period_ms: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class DrainRequest(_message.Message):
    __slots__ = ("duration_ms", "reason", "timestamp_ms")
    class Reason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REASON_UNSPECIFIED: _ClassVar[DrainRequest.Reason]
        REASON_CONFIG_RELOAD: _ClassVar[DrainRequest.Reason]
        REASON_MAINTENANCE: _ClassVar[DrainRequest.Reason]
        REASON_HEALTH_CHECK_FAILED: _ClassVar[DrainRequest.Reason]
        REASON_MANUAL: _ClassVar[DrainRequest.Reason]
    REASON_UNSPECIFIED: DrainRequest.Reason
    REASON_CONFIG_RELOAD: DrainRequest.Reason
    REASON_MAINTENANCE: DrainRequest.Reason
    REASON_HEALTH_CHECK_FAILED: DrainRequest.Reason
    REASON_MANUAL: DrainRequest.Reason
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    duration_ms: int
    reason: int
    timestamp_ms: int
    def __init__(self, duration_ms: _Optional[int] = ..., reason: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class LogMessage(_message.Message):
    __slots__ = ("level", "message", "correlation_id", "fields", "timestamp_ms")
    class FieldsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    level: int
    message: str
    correlation_id: str
    fields: _containers.ScalarMap[str, str]
    timestamp_ms: int
    def __init__(self, level: _Optional[int] = ..., message: _Optional[str] = ..., correlation_id: _Optional[str] = ..., fields: _Optional[_Mapping[str, str]] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class MetricsReport(_message.Message):
    __slots__ = ("agent_id", "timestamp_ms", "interval_ms", "counters", "gauges", "histograms")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    COUNTERS_FIELD_NUMBER: _ClassVar[int]
    GAUGES_FIELD_NUMBER: _ClassVar[int]
    HISTOGRAMS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    timestamp_ms: int
    interval_ms: int
    counters: _containers.RepeatedCompositeFieldContainer[CounterMetric]
    gauges: _containers.RepeatedCompositeFieldContainer[GaugeMetric]
    histograms: _containers.RepeatedCompositeFieldContainer[HistogramMetric]
    def __init__(self, agent_id: _Optional[str] = ..., timestamp_ms: _Optional[int] = ..., interval_ms: _Optional[int] = ..., counters: _Optional[_Iterable[_Union[CounterMetric, _Mapping]]] = ..., gauges: _Optional[_Iterable[_Union[GaugeMetric, _Mapping]]] = ..., histograms: _Optional[_Iterable[_Union[HistogramMetric, _Mapping]]] = ...) -> None: ...

class CounterMetric(_message.Message):
    __slots__ = ("name", "help", "labels", "value")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    HELP_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    help: str
    labels: _containers.ScalarMap[str, str]
    value: int
    def __init__(self, name: _Optional[str] = ..., help: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., value: _Optional[int] = ...) -> None: ...

class GaugeMetric(_message.Message):
    __slots__ = ("name", "help", "labels", "value")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    HELP_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    help: str
    labels: _containers.ScalarMap[str, str]
    value: float
    def __init__(self, name: _Optional[str] = ..., help: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., value: _Optional[float] = ...) -> None: ...

class HistogramMetric(_message.Message):
    __slots__ = ("name", "help", "labels", "sum", "count", "buckets")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    HELP_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    SUM_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    BUCKETS_FIELD_NUMBER: _ClassVar[int]
    name: str
    help: str
    labels: _containers.ScalarMap[str, str]
    sum: float
    count: int
    buckets: _containers.RepeatedCompositeFieldContainer[HistogramBucket]
    def __init__(self, name: _Optional[str] = ..., help: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., sum: _Optional[float] = ..., count: _Optional[int] = ..., buckets: _Optional[_Iterable[_Union[HistogramBucket, _Mapping]]] = ...) -> None: ...

class HistogramBucket(_message.Message):
    __slots__ = ("le", "count")
    LE_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    le: float
    count: int
    def __init__(self, le: _Optional[float] = ..., count: _Optional[int] = ...) -> None: ...

class FlowControlSignal(_message.Message):
    __slots__ = ("correlation_id", "action", "buffer_available", "timestamp_ms")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    BUFFER_AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    action: int
    buffer_available: int
    timestamp_ms: int
    def __init__(self, correlation_id: _Optional[str] = ..., action: _Optional[int] = ..., buffer_available: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class RequestMetadata(_message.Message):
    __slots__ = ("correlation_id", "request_id", "client_ip", "client_port", "server_name", "protocol", "tls_version", "route_id", "upstream_id", "timestamp_ms", "traceparent")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_IP_FIELD_NUMBER: _ClassVar[int]
    CLIENT_PORT_FIELD_NUMBER: _ClassVar[int]
    SERVER_NAME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    TLS_VERSION_FIELD_NUMBER: _ClassVar[int]
    ROUTE_ID_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    TRACEPARENT_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    request_id: str
    client_ip: str
    client_port: int
    server_name: str
    protocol: str
    tls_version: str
    route_id: str
    upstream_id: str
    timestamp_ms: int
    traceparent: str
    def __init__(self, correlation_id: _Optional[str] = ..., request_id: _Optional[str] = ..., client_ip: _Optional[str] = ..., client_port: _Optional[int] = ..., server_name: _Optional[str] = ..., protocol: _Optional[str] = ..., tls_version: _Optional[str] = ..., route_id: _Optional[str] = ..., upstream_id: _Optional[str] = ..., timestamp_ms: _Optional[int] = ..., traceparent: _Optional[str] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    def __init__(self, name: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class HeaderOp(_message.Message):
    __slots__ = ("set", "add", "remove")
    SET_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    set: Header
    add: Header
    remove: str
    def __init__(self, set: _Optional[_Union[Header, _Mapping]] = ..., add: _Optional[_Union[Header, _Mapping]] = ..., remove: _Optional[str] = ...) -> None: ...

class RequestHeadersEvent(_message.Message):
    __slots__ = ("metadata", "method", "uri", "http_version", "headers")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    HTTP_VERSION_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    method: str
    uri: str
    http_version: str
    headers: _containers.RepeatedCompositeFieldContainer[Header]
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., method: _Optional[str] = ..., uri: _Optional[str] = ..., http_version: _Optional[str] = ..., headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ...) -> None: ...

class ResponseHeadersEvent(_message.Message):
    __slots__ = ("correlation_id", "status_code", "headers")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    status_code: int
    headers: _containers.RepeatedCompositeFieldContainer[Header]
    def __init__(self, correlation_id: _Optional[str] = ..., status_code: _Optional[int] = ..., headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ...) -> None: ...

class BodyChunkEvent(_message.Message):
    __slots__ = ("correlation_id", "chunk_index", "data", "is_last", "total_size", "bytes_transferred", "proxy_buffer_available", "timestamp_ms")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CHUNK_INDEX_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    IS_LAST_FIELD_NUMBER: _ClassVar[int]
    TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    BYTES_TRANSFERRED_FIELD_NUMBER: _ClassVar[int]
    PROXY_BUFFER_AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    chunk_index: int
    data: bytes
    is_last: bool
    total_size: int
    bytes_transferred: int
    proxy_buffer_available: int
    timestamp_ms: int
    def __init__(self, correlation_id: _Optional[str] = ..., chunk_index: _Optional[int] = ..., data: _Optional[bytes] = ..., is_last: bool = ..., total_size: _Optional[int] = ..., bytes_transferred: _Optional[int] = ..., proxy_buffer_available: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class WebSocketFrameEvent(_message.Message):
    __slots__ = ("correlation_id", "client_to_server", "frame_type", "payload")
    class FrameType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        FRAME_TYPE_UNSPECIFIED: _ClassVar[WebSocketFrameEvent.FrameType]
        FRAME_TYPE_TEXT: _ClassVar[WebSocketFrameEvent.FrameType]
        FRAME_TYPE_BINARY: _ClassVar[WebSocketFrameEvent.FrameType]
        FRAME_TYPE_PING: _ClassVar[WebSocketFrameEvent.FrameType]
        FRAME_TYPE_PONG: _ClassVar[WebSocketFrameEvent.FrameType]
        FRAME_TYPE_CLOSE: _ClassVar[WebSocketFrameEvent.FrameType]
    FRAME_TYPE_UNSPECIFIED: WebSocketFrameEvent.FrameType
    FRAME_TYPE_TEXT: WebSocketFrameEvent.FrameType
    FRAME_TYPE_BINARY: WebSocketFrameEvent.FrameType
    FRAME_TYPE_PING: WebSocketFrameEvent.FrameType
    FRAME_TYPE_PONG: WebSocketFrameEvent.FrameType
    FRAME_TYPE_CLOSE: WebSocketFrameEvent.FrameType
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_TO_SERVER_FIELD_NUMBER: _ClassVar[int]
    FRAME_TYPE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    client_to_server: bool
    frame_type: int
    payload: bytes
    def __init__(self, correlation_id: _Optional[str] = ..., client_to_server: bool = ..., frame_type: _Optional[int] = ..., payload: _Optional[bytes] = ...) -> None: ...

class GuardrailInspectEvent(_message.Message):
    __slots__ = ("correlation_id", "content", "content_type", "model", "context_json")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_JSON_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    content: str
    content_type: int
    model: str
    context_json: str
    def __init__(self, correlation_id: _Optional[str] = ..., content: _Optional[str] = ..., content_type: _Optional[int] = ..., model: _Optional[str] = ..., context_json: _Optional[str] = ...) -> None: ...

class RequestCompleteEvent(_message.Message):
    __slots__ = ("correlation_id", "status_code", "duration_ms", "bytes_received", "bytes_sent", "upstream", "from_cache", "error")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    BYTES_RECEIVED_FIELD_NUMBER: _ClassVar[int]
    BYTES_SENT_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_FIELD_NUMBER: _ClassVar[int]
    FROM_CACHE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    status_code: int
    duration_ms: int
    bytes_received: int
    bytes_sent: int
    upstream: str
    from_cache: bool
    error: str
    def __init__(self, correlation_id: _Optional[str] = ..., status_code: _Optional[int] = ..., duration_ms: _Optional[int] = ..., bytes_received: _Optional[int] = ..., bytes_sent: _Optional[int] = ..., upstream: _Optional[str] = ..., from_cache: bool = ..., error: _Optional[str] = ...) -> None: ...

class ConfigureEvent(_message.Message):
    __slots__ = ("config_json", "config_version", "is_initial", "timestamp_ms")
    CONFIG_JSON_FIELD_NUMBER: _ClassVar[int]
    CONFIG_VERSION_FIELD_NUMBER: _ClassVar[int]
    IS_INITIAL_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    config_json: str
    config_version: str
    is_initial: bool
    timestamp_ms: int
    def __init__(self, config_json: _Optional[str] = ..., config_version: _Optional[str] = ..., is_initial: bool = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class Ping(_message.Message):
    __slots__ = ("sequence", "timestamp_ms")
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    sequence: int
    timestamp_ms: int
    def __init__(self, sequence: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class Pong(_message.Message):
    __slots__ = ("sequence", "ping_timestamp_ms", "timestamp_ms")
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    PING_TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    sequence: int
    ping_timestamp_ms: int
    timestamp_ms: int
    def __init__(self, sequence: _Optional[int] = ..., ping_timestamp_ms: _Optional[int] = ..., timestamp_ms: _Optional[int] = ...) -> None: ...

class AuditMetadata(_message.Message):
    __slots__ = ("tags", "rule_ids", "confidence", "reason_codes", "custom")
    class CustomEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    TAGS_FIELD_NUMBER: _ClassVar[int]
    RULE_IDS_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    REASON_CODES_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_FIELD_NUMBER: _ClassVar[int]
    tags: _containers.RepeatedScalarFieldContainer[str]
    rule_ids: _containers.RepeatedScalarFieldContainer[str]
    confidence: float
    reason_codes: _containers.RepeatedScalarFieldContainer[str]
    custom: _containers.ScalarMap[str, str]
    def __init__(self, tags: _Optional[_Iterable[str]] = ..., rule_ids: _Optional[_Iterable[str]] = ..., confidence: _Optional[float] = ..., reason_codes: _Optional[_Iterable[str]] = ..., custom: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AllowDecision(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BlockDecision(_message.Message):
    __slots__ = ("status", "body", "headers")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    status: int
    body: str
    headers: _containers.RepeatedCompositeFieldContainer[Header]
    def __init__(self, status: _Optional[int] = ..., body: _Optional[str] = ..., headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ...) -> None: ...

class RedirectDecision(_message.Message):
    __slots__ = ("url", "status")
    URL_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    url: str
    status: int
    def __init__(self, url: _Optional[str] = ..., status: _Optional[int] = ...) -> None: ...

class ChallengeDecision(_message.Message):
    __slots__ = ("challenge_type", "params")
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CHALLENGE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    challenge_type: str
    params: _containers.ScalarMap[str, str]
    def __init__(self, challenge_type: _Optional[str] = ..., params: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ProxyToAgent(_message.Message):
    __slots__ = ("handshake", "request_headers", "request_body_chunk", "response_headers", "response_body_chunk", "websocket_frame", "guardrail", "request_complete", "cancel", "configure", "ping")
    HANDSHAKE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_HEADERS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_CHUNK_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_CHUNK_FIELD_NUMBER: _ClassVar[int]
    WEBSOCKET_FRAME_FIELD_NUMBER: _ClassVar[int]
    GUARDRAIL_FIELD_NUMBER: _ClassVar[int]
    REQUEST_COMPLETE_FIELD_NUMBER: _ClassVar[int]
    CANCEL_FIELD_NUMBER: _ClassVar[int]
    CONFIGURE_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    handshake: HandshakeRequest
    request_headers: RequestHeadersEvent
    request_body_chunk: BodyChunkEvent
    response_headers: ResponseHeadersEvent
    response_body_chunk: BodyChunkEvent
    websocket_frame: WebSocketFrameEvent
    guardrail: GuardrailInspectEvent
    request_complete: RequestCompleteEvent
    cancel: CancelRequest
    configure: ConfigureEvent
    ping: Ping
    def __init__(self, handshake: _Optional[_Union[HandshakeRequest, _Mapping]] = ..., request_headers: _Optional[_Union[RequestHeadersEvent, _Mapping]] = ..., request_body_chunk: _Optional[_Union[BodyChunkEvent, _Mapping]] = ..., response_headers: _Optional[_Union[ResponseHeadersEvent, _Mapping]] = ..., response_body_chunk: _Optional[_Union[BodyChunkEvent, _Mapping]] = ..., websocket_frame: _Optional[_Union[WebSocketFrameEvent, _Mapping]] = ..., guardrail: _Optional[_Union[GuardrailInspectEvent, _Mapping]] = ..., request_complete: _Optional[_Union[RequestCompleteEvent, _Mapping]] = ..., cancel: _Optional[_Union[CancelRequest, _Mapping]] = ..., configure: _Optional[_Union[ConfigureEvent, _Mapping]] = ..., ping: _Optional[_Union[Ping, _Mapping]] = ...) -> None: ...

class AgentToProxy(_message.Message):
    __slots__ = ("handshake", "response", "health", "metrics", "config_update", "flow_control", "pong", "log")
    HANDSHAKE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    HEALTH_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_UPDATE_FIELD_NUMBER: _ClassVar[int]
    FLOW_CONTROL_FIELD_NUMBER: _ClassVar[int]
    PONG_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    handshake: HandshakeResponse
    response: AgentResponse
    health: HealthStatus
    metrics: MetricsReport
    config_update: ConfigUpdateRequest
    flow_control: FlowControlSignal
    pong: Pong
    log: LogMessage
    def __init__(self, handshake: _Optional[_Union[HandshakeResponse, _Mapping]] = ..., response: _Optional[_Union[AgentResponse, _Mapping]] = ..., health: _Optional[_Union[HealthStatus, _Mapping]] = ..., metrics: _Optional[_Union[MetricsReport, _Mapping]] = ..., config_update: _Optional[_Union[ConfigUpdateRequest, _Mapping]] = ..., flow_control: _Optional[_Union[FlowControlSignal, _Mapping]] = ..., pong: _Optional[_Union[Pong, _Mapping]] = ..., log: _Optional[_Union[LogMessage, _Mapping]] = ...) -> None: ...

class AgentResponse(_message.Message):
    __slots__ = ("correlation_id", "allow", "block", "redirect", "challenge", "request_headers", "response_headers", "audit", "processing_time_ms", "needs_more")
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    REDIRECT_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_HEADERS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADERS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    PROCESSING_TIME_MS_FIELD_NUMBER: _ClassVar[int]
    NEEDS_MORE_FIELD_NUMBER: _ClassVar[int]
    correlation_id: str
    allow: AllowDecision
    block: BlockDecision
    redirect: RedirectDecision
    challenge: ChallengeDecision
    request_headers: _containers.RepeatedCompositeFieldContainer[HeaderOp]
    response_headers: _containers.RepeatedCompositeFieldContainer[HeaderOp]
    audit: AuditMetadata
    processing_time_ms: int
    needs_more: bool
    def __init__(self, correlation_id: _Optional[str] = ..., allow: _Optional[_Union[AllowDecision, _Mapping]] = ..., block: _Optional[_Union[BlockDecision, _Mapping]] = ..., redirect: _Optional[_Union[RedirectDecision, _Mapping]] = ..., challenge: _Optional[_Union[ChallengeDecision, _Mapping]] = ..., request_headers: _Optional[_Iterable[_Union[HeaderOp, _Mapping]]] = ..., response_headers: _Optional[_Iterable[_Union[HeaderOp, _Mapping]]] = ..., audit: _Optional[_Union[AuditMetadata, _Mapping]] = ..., processing_time_ms: _Optional[int] = ..., needs_more: bool = ...) -> None: ...

class AgentControl(_message.Message):
    __slots__ = ("health", "metrics", "config_update", "log")
    HEALTH_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_UPDATE_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    health: HealthStatus
    metrics: MetricsReport
    config_update: ConfigUpdateRequest
    log: LogMessage
    def __init__(self, health: _Optional[_Union[HealthStatus, _Mapping]] = ..., metrics: _Optional[_Union[MetricsReport, _Mapping]] = ..., config_update: _Optional[_Union[ConfigUpdateRequest, _Mapping]] = ..., log: _Optional[_Union[LogMessage, _Mapping]] = ...) -> None: ...

class ProxyControl(_message.Message):
    __slots__ = ("configure", "shutdown", "drain", "config_response")
    CONFIGURE_FIELD_NUMBER: _ClassVar[int]
    SHUTDOWN_FIELD_NUMBER: _ClassVar[int]
    DRAIN_FIELD_NUMBER: _ClassVar[int]
    CONFIG_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    configure: ConfigureEvent
    shutdown: ShutdownRequest
    drain: DrainRequest
    config_response: ConfigUpdateResponse
    def __init__(self, configure: _Optional[_Union[ConfigureEvent, _Mapping]] = ..., shutdown: _Optional[_Union[ShutdownRequest, _Mapping]] = ..., drain: _Optional[_Union[DrainRequest, _Mapping]] = ..., config_response: _Optional[_Union[ConfigUpdateResponse, _Mapping]] = ...) -> None: ...
