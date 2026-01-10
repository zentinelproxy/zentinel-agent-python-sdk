#!/bin/bash
#
# Sentinel Agent Python SDK Integration Tests
# Tests the Python SDK against a running Sentinel proxy
#
# Prerequisites:
# - Sentinel built at SENTINEL_PATH or /Users/zara/Development/github.com/raskell-io/sentinel
# - Python SDK installed (uv sync)
# - curl installed
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SENTINEL_PATH="${SENTINEL_PATH:-/Users/zara/Development/github.com/raskell-io/sentinel}"

TEST_DIR="/tmp/sentinel-python-sdk-test-$$"
PROXY_PORT=28080
BACKEND_PORT=28081

ECHO_SOCKET="$TEST_DIR/echo.sock"
BLOCKING_SOCKET="$TEST_DIR/blocking.sock"
HEADER_SOCKET="$TEST_DIR/header.sock"
PROXY_CONFIG="$TEST_DIR/config.kdl"

PROXY_PID=""
ECHO_PID=""
BLOCKING_PID=""
HEADER_PID=""
BACKEND_PID=""

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++)) || true
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++)) || true
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    ((TESTS_RUN++)) || true
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    # Kill processes if they exist
    [[ -n "$PROXY_PID" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill -TERM "$ECHO_PID" 2>/dev/null || true
    [[ -n "$BLOCKING_PID" ]] && kill -TERM "$BLOCKING_PID" 2>/dev/null || true
    [[ -n "$HEADER_PID" ]] && kill -TERM "$HEADER_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -TERM "$BACKEND_PID" 2>/dev/null || true

    # Wait for processes to terminate
    sleep 1

    # Force kill if still running
    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill -9 "$ECHO_PID" 2>/dev/null || true
    [[ -n "$BLOCKING_PID" ]] && kill -9 "$BLOCKING_PID" 2>/dev/null || true
    [[ -n "$HEADER_PID" ]] && kill -9 "$HEADER_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -9 "$BACKEND_PID" 2>/dev/null || true

    # Remove test directory
    rm -rf "$TEST_DIR"
}

# Set up cleanup on exit
trap cleanup EXIT INT TERM

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -f "$SENTINEL_PATH/target/release/sentinel" ]]; then
        log_failure "Sentinel binary not found at $SENTINEL_PATH/target/release/sentinel"
        log_info "Build Sentinel with: cd $SENTINEL_PATH && cargo build --release"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_failure "curl is required but not installed"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        log_failure "python3 is required but not installed"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Create test directory and config
setup_test_environment() {
    log_info "Setting up test environment..."
    mkdir -p "$TEST_DIR"

    # Create test configuration for Sentinel
    cat > "$PROXY_CONFIG" <<'EOFCONFIG'
system {
    worker-threads 2
    max-connections 1000
    graceful-shutdown-timeout-secs 5
}

listeners {
    listener "http" {
        address "127.0.0.1:PROXY_PORT_PLACEHOLDER"
        protocol "http"
        request-timeout-secs 30
    }
}

routes {
    route "echo-test" {
        priority "high"
        matches {
            path-prefix "/echo/"
        }
        upstream "test-backend"
        agents ["echo-agent"]
        policies {
            failure-mode "open"
        }
    }

    route "blocking-test" {
        priority "high"
        matches {
            path-prefix "/blocking/"
        }
        upstream "test-backend"
        agents ["blocking-agent"]
        policies {
            failure-mode "closed"
        }
    }

    route "header-test" {
        priority "high"
        matches {
            path-prefix "/headers/"
        }
        upstream "test-backend"
        agents ["header-agent"]
        policies {
            failure-mode "open"
        }
    }

    route "multi-agent-test" {
        priority "high"
        matches {
            path-prefix "/multi/"
        }
        upstream "test-backend"
        agents ["echo-agent" "blocking-agent"]
    }

    route "default" {
        priority "low"
        matches {
            path-prefix "/"
        }
        upstream "test-backend"
    }
}

upstreams {
    upstream "test-backend" {
        targets {
            target {
                address "127.0.0.1:BACKEND_PORT_PLACEHOLDER"
                weight 1
            }
        }
        load-balancing "round_robin"
    }
}

agents {
    agent "echo-agent" {
        type "custom"
        transport "unix_socket" {
            path "ECHO_SOCKET_PLACEHOLDER"
        }
        events ["request_headers"]
        timeout-ms 5000
        failure-mode "open"
    }

    agent "blocking-agent" {
        type "custom"
        transport "unix_socket" {
            path "BLOCKING_SOCKET_PLACEHOLDER"
        }
        events ["request_headers"]
        timeout-ms 5000
        failure-mode "closed"
    }

    agent "header-agent" {
        type "custom"
        transport "unix_socket" {
            path "HEADER_SOCKET_PLACEHOLDER"
        }
        events ["request_headers"]
        timeout-ms 5000
        failure-mode "open"
    }
}

limits {
    max-header-count 100
    max-header-size-bytes 8192
    max-body-size-bytes 1048576
}

observability {
    logging {
        level "debug"
        format "json"
    }
}
EOFCONFIG

    # Replace placeholders with actual values
    sed -i '' "s|PROXY_PORT_PLACEHOLDER|$PROXY_PORT|g" "$PROXY_CONFIG"
    sed -i '' "s|BACKEND_PORT_PLACEHOLDER|$BACKEND_PORT|g" "$PROXY_CONFIG"
    sed -i '' "s|ECHO_SOCKET_PLACEHOLDER|$ECHO_SOCKET|g" "$PROXY_CONFIG"
    sed -i '' "s|BLOCKING_SOCKET_PLACEHOLDER|$BLOCKING_SOCKET|g" "$PROXY_CONFIG"
    sed -i '' "s|HEADER_SOCKET_PLACEHOLDER|$HEADER_SOCKET|g" "$PROXY_CONFIG"

    log_info "Test configuration created"
}

# Start simple HTTP backend
start_backend() {
    log_info "Starting test backend on port $BACKEND_PORT..."

    python3 -c "
import http.server
import json
import socketserver

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Backend', 'python-test')
        self.end_headers()
        response = {
            'path': self.path,
            'method': 'GET',
            'headers': dict(self.headers),
        }
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            'path': self.path,
            'method': 'POST',
            'body_length': len(body),
        }
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress logging

with socketserver.TCPServer(('127.0.0.1', $BACKEND_PORT), Handler) as httpd:
    httpd.serve_forever()
" > "$TEST_DIR/backend.log" 2>&1 &

    BACKEND_PID=$!
    sleep 1

    if curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null 2>&1; then
        log_info "Backend started (PID: $BACKEND_PID)"
        return 0
    else
        log_failure "Backend failed to start"
        return 1
    fi
}

# Start Python agent
start_python_agent() {
    local name=$1
    local script=$2
    local socket=$3
    local extra_args=${4:-}

    log_info "Starting $name agent..."

    cd "$SDK_ROOT"
    python3 "$script" --socket "$socket" --log-level DEBUG $extra_args \
        > "$TEST_DIR/${name}-agent.log" 2>&1 &

    local pid=$!

    # Wait for socket to be created
    local retries=20
    while [[ ! -S "$socket" ]] && [[ $retries -gt 0 ]]; do
        sleep 0.25
        ((retries--))
    done

    if [[ -S "$socket" ]]; then
        log_info "$name agent started (PID: $pid)"
        echo $pid
        return 0
    else
        log_failure "$name agent failed to start"
        cat "$TEST_DIR/${name}-agent.log" | tail -20
        return 1
    fi
}

# Start Sentinel proxy
start_proxy() {
    log_info "Starting Sentinel proxy..."

    cd "$SENTINEL_PATH"
    RUST_LOG=debug SENTINEL_CONFIG="$PROXY_CONFIG" \
        ./target/release/sentinel \
        > "$TEST_DIR/proxy.log" 2>&1 &

    PROXY_PID=$!

    # Wait for proxy to be ready
    local retries=30
    while ! curl -sf "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; do
        sleep 0.5
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            log_failure "Proxy failed to start"
            cat "$TEST_DIR/proxy.log" | tail -30
            return 1
        fi
    done

    log_info "Proxy started (PID: $PROXY_PID)"
    return 0
}

# ============================================================================
# Tests
# ============================================================================

test_echo_agent() {
    log_test "Echo agent adds response headers"

    local response=$(curl -s -i "http://127.0.0.1:$PROXY_PORT/echo/test")

    if echo "$response" | grep -qi "X-Echo-Agent: python-echo-agent"; then
        log_success "Echo agent added X-Echo-Agent header"
    else
        log_failure "Echo agent did not add X-Echo-Agent header"
        echo "$response"
    fi

    if echo "$response" | grep -qi "X-Echo-Method: GET"; then
        log_success "Echo agent added X-Echo-Method header"
    else
        log_failure "Echo agent did not add X-Echo-Method header"
    fi

    if echo "$response" | grep -qi "X-Echo-Path: /echo/test"; then
        log_success "Echo agent added X-Echo-Path header"
    else
        log_failure "Echo agent did not add X-Echo-Path header"
    fi

    if echo "$response" | grep -qi "X-Echo-Correlation-Id:"; then
        log_success "Echo agent added correlation ID header"
    else
        log_failure "Echo agent did not add correlation ID header"
    fi
}

test_blocking_agent_allows() {
    log_test "Blocking agent allows non-blocked paths"

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/blocking/allowed/path")

    if [[ "$status" == "200" ]]; then
        log_success "Blocking agent allowed request to /blocking/allowed/path"
    else
        log_failure "Blocking agent incorrectly blocked /blocking/allowed/path (status: $status)"
    fi
}

test_blocking_agent_blocks() {
    log_test "Blocking agent blocks configured paths"

    # Test /blocked path
    local response=$(curl -s -i "http://127.0.0.1:$PROXY_PORT/blocking/blocked/secret")
    local status=$(echo "$response" | head -1 | awk '{print $2}')

    if [[ "$status" == "403" ]]; then
        log_success "Blocking agent blocked /blocking/blocked with 403"
    else
        log_failure "Blocking agent did not block /blocking/blocked (status: $status)"
    fi

    if echo "$response" | grep -qi "X-Blocked-By: python-blocking-agent"; then
        log_success "Blocking agent added X-Blocked-By header"
    else
        log_failure "Blocking agent did not add X-Blocked-By header"
    fi

    if echo "$response" | grep -q '"blocked_by": "python-blocking-agent"'; then
        log_success "Blocking agent returned JSON body"
    else
        log_failure "Blocking agent did not return expected JSON body"
    fi
}

test_header_mutation_agent() {
    log_test "Header mutation agent modifies headers"

    local response=$(curl -s -i \
        -H "X-Internal-Token: secret123" \
        "http://127.0.0.1:$PROXY_PORT/headers/test")

    if echo "$response" | grep -qi "X-Request-Processed: true"; then
        log_success "Header agent added X-Request-Processed header"
    else
        log_failure "Header agent did not add X-Request-Processed header"
    fi

    if echo "$response" | grep -qi "X-Response-Processed: true"; then
        log_success "Header agent added X-Response-Processed header"
    else
        log_failure "Header agent did not add X-Response-Processed header"
    fi
}

test_multi_agent_chain() {
    log_test "Multiple agents process request in chain"

    # Test allowed path with multi-agent
    local response=$(curl -s -i "http://127.0.0.1:$PROXY_PORT/multi/allowed")

    # Should have echo agent headers
    if echo "$response" | grep -qi "X-Echo-Agent:"; then
        log_success "Echo agent processed in multi-agent chain"
    else
        log_failure "Echo agent did not process in multi-agent chain"
    fi

    # Should have blocking agent header (for allowed path)
    if echo "$response" | grep -qi "X-Blocking-Agent: checked"; then
        log_success "Blocking agent processed in multi-agent chain"
    else
        log_failure "Blocking agent did not process in multi-agent chain"
    fi
}

test_multi_agent_block_stops_chain() {
    log_test "Block decision stops agent chain"

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/multi/blocked/test")

    if [[ "$status" == "403" ]]; then
        log_success "Block decision in chain returned 403"
    else
        log_failure "Block decision in chain did not return 403 (got: $status)"
    fi
}

test_agent_timeout_failopen() {
    log_test "Agent timeout with fail-open mode"

    # Kill echo agent to simulate timeout
    if [[ -n "$ECHO_PID" ]]; then
        kill -TERM "$ECHO_PID" 2>/dev/null || true
        ECHO_PID=""
        sleep 1
    fi

    # Should still work (fail-open)
    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/echo/test")

    if [[ "$status" == "200" ]]; then
        log_success "Fail-open mode allowed request when agent unavailable"
    else
        log_failure "Fail-open mode did not work (status: $status)"
    fi

    # Restart echo agent for remaining tests
    ECHO_PID=$(start_python_agent "echo" \
        "$SCRIPT_DIR/agents/echo_agent.py" \
        "$ECHO_SOCKET")
    sleep 1
}

test_post_request() {
    log_test "POST request through agent"

    local response=$(curl -s -i -X POST \
        -H "Content-Type: application/json" \
        -d '{"test": "data"}' \
        "http://127.0.0.1:$PROXY_PORT/echo/post")

    if echo "$response" | grep -qi "X-Echo-Method: POST"; then
        log_success "Echo agent correctly identified POST method"
    else
        log_failure "Echo agent did not identify POST method"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "=============================================="
    echo "Sentinel Agent Python SDK Integration Tests"
    echo "=============================================="
    echo

    check_prerequisites
    setup_test_environment

    # Start services
    start_backend || exit 1

    ECHO_PID=$(start_python_agent "echo" \
        "$SCRIPT_DIR/agents/echo_agent.py" \
        "$ECHO_SOCKET") || exit 1

    BLOCKING_PID=$(start_python_agent "blocking" \
        "$SCRIPT_DIR/agents/blocking_agent.py" \
        "$BLOCKING_SOCKET" \
        "--blocked-paths /blocked /admin /secret") || exit 1

    HEADER_PID=$(start_python_agent "header" \
        "$SCRIPT_DIR/agents/header_mutation_agent.py" \
        "$HEADER_SOCKET") || exit 1

    start_proxy || exit 1

    # Wait for everything to stabilize
    sleep 2

    # Run tests
    echo
    echo "Running tests..."
    echo

    test_echo_agent
    test_blocking_agent_allows
    test_blocking_agent_blocks
    test_header_mutation_agent
    test_multi_agent_chain
    test_multi_agent_block_stops_chain
    test_post_request
    test_agent_timeout_failopen

    # Print summary
    echo
    echo "=============================================="
    echo "Test Summary"
    echo "=============================================="
    echo "Tests run:    $TESTS_RUN"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    else
        echo "Tests failed: $TESTS_FAILED"
    fi
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        echo
        echo "The Python SDK is compatible with Sentinel."
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        echo
        echo "Check logs for details:"
        echo "  Proxy log: $TEST_DIR/proxy.log"
        echo "  Echo agent log: $TEST_DIR/echo-agent.log"
        echo "  Blocking agent log: $TEST_DIR/blocking-agent.log"
        echo "  Header agent log: $TEST_DIR/header-agent.log"
        exit 1
    fi
}

main "$@"
