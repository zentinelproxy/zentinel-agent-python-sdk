"""Generated protobuf and gRPC code for agent protocol v2.

`agent_v2.proto` is a copy of `crates/agent-protocol/proto/agent_v2.proto`
in zentinelproxy/zentinel. Regenerate after updating it, from `src/`, with
grpcio-tools 1.72.1 (the oldest generator whose output the declared
`grpcio`/`protobuf` floors accept):

    python -m grpc_tools.protoc -I . --python_out=. --pyi_out=. \
        --grpc_python_out=. zentinel_agent_sdk/v2/proto/agent_v2.proto
"""
