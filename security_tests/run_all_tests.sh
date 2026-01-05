#!/bin/bash
#
# HSIP Phase 1 Security Testing Suite
# Runs comprehensive attack simulations using mitmproxy
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  HSIP Phase 1 Security Testing Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}[*] Checking prerequisites...${NC}"

if ! command -v mitmproxy &> /dev/null; then
    echo -e "${RED}[!] mitmproxy not found. Install with: pip install mitmproxy${NC}"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo -e "${RED}[!] curl not found. Please install curl${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Prerequisites OK${NC}"
echo ""

# Check if HSIP is running
echo -e "${YELLOW}[*] Checking HSIP services...${NC}"

if curl -s http://127.0.0.1:8787/status > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] HSIP daemon running on port 8787${NC}"
else
    echo -e "${YELLOW}[!] HSIP daemon not responding on port 8787${NC}"
    echo -e "${YELLOW}[!] Some tests may fail. Start daemon with: hsip-cli daemon${NC}"
fi

if curl -s http://127.0.0.1:8080 > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] HSIP gateway running on port 8080${NC}"
else
    echo -e "${YELLOW}[!] HSIP gateway not responding on port 8080${NC}"
    echo -e "${YELLOW}[!] Some tests may fail. Start gateway with: hsip-gateway${NC}"
fi

echo ""

# Test 1: Status API Security
echo -e "${BLUE}[1/8] Testing HTTP Status API (Port 8787)...${NC}"
{
    echo "=== Status API Tests ==="
    echo ""

    echo "Test: Normal status request"
    curl -s http://127.0.0.1:8787/status
    echo ""

    echo "Test: Malformed POST data"
    curl -s -X POST http://127.0.0.1:8787/status -d "malformed{{{data" || true
    echo ""

    echo "Test: Path traversal attempt"
    curl -s http://127.0.0.1:8787/../../../etc/passwd || true
    echo ""

    echo "Test: DELETE method (should fail)"
    curl -s -X DELETE http://127.0.0.1:8787/status || true
    echo ""

    echo "Test: Oversized header"
    curl -s -H "X-Large: $(python3 -c 'print("A"*10000)')" http://127.0.0.1:8787/status || true
    echo ""

} > "$RESULTS_DIR/01_api_tests_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/01_api_tests_$TIMESTAMP.log${NC}"
echo ""

# Test 2: Rate Limiting
echo -e "${BLUE}[2/8] Testing Rate Limiting...${NC}"
{
    echo "=== Rate Limiting Test ==="
    echo "Sending 100 concurrent requests..."

    for i in {1..100}; do
        curl -s http://127.0.0.1:8787/status > /dev/null 2>&1 &
    done
    wait

    echo "Completed 100 requests"
    echo "Check if daemon still responsive:"
    curl -s http://127.0.0.1:8787/status

} > "$RESULTS_DIR/02_rate_limit_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/02_rate_limit_$TIMESTAMP.log${NC}"
echo ""

# Test 3: Large Payload
echo -e "${BLUE}[3/8] Testing Large Payload Handling...${NC}"
{
    echo "=== Large Payload Test ==="
    echo "Sending 10MB payload..."

    dd if=/dev/zero bs=1M count=10 2>/dev/null | \
        curl -s -X POST http://127.0.0.1:8787/status --data-binary @- || true

    echo ""
    echo "Test completed"

} > "$RESULTS_DIR/03_large_payload_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/03_large_payload_$TIMESTAMP.log${NC}"
echo ""

# Test 4: Header Injection (requires mitmproxy)
echo -e "${BLUE}[4/8] Testing Header Injection Attack...${NC}"
{
    echo "=== Header Injection Test ==="
    echo "Starting mitmproxy with header injection script..."
    echo "Note: This runs in background for 10 seconds"
    echo ""

    timeout 10s mitmdump -s "$SCRIPT_DIR/header_injection.py" -p 8081 --ssl-insecure 2>&1 &
    MITM_PID=$!
    sleep 2

    echo "Sending test request through proxy..."
    curl -x http://127.0.0.1:8081 -s http://example.com > /dev/null 2>&1 || true

    sleep 2
    kill $MITM_PID 2>/dev/null || true
    wait $MITM_PID 2>/dev/null || true

    echo "Test completed"

} > "$RESULTS_DIR/04_header_injection_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/04_header_injection_$TIMESTAMP.log${NC}"
echo ""

# Test 5: Response Tampering
echo -e "${BLUE}[5/8] Testing Response Tampering Attack...${NC}"
{
    echo "=== Response Tampering Test ==="
    echo "Starting mitmproxy with response tampering script..."
    echo ""

    timeout 10s mitmdump -s "$SCRIPT_DIR/response_tamper.py" -p 8082 --ssl-insecure 2>&1 &
    MITM_PID=$!
    sleep 2

    echo "Sending test request through proxy..."
    curl -x http://127.0.0.1:8082 -s http://example.com > /dev/null 2>&1 || true

    sleep 2
    kill $MITM_PID 2>/dev/null || true
    wait $MITM_PID 2>/dev/null || true

    echo "Test completed"

} > "$RESULTS_DIR/05_response_tamper_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/05_response_tamper_$TIMESTAMP.log${NC}"
echo ""

# Test 6: SSL Stripping
echo -e "${BLUE}[6/8] Testing SSL Stripping Attack...${NC}"
{
    echo "=== SSL Stripping Test ==="
    echo "Starting mitmproxy with SSL stripping script..."
    echo ""

    timeout 10s mitmdump -s "$SCRIPT_DIR/ssl_strip.py" -p 8083 --ssl-insecure 2>&1 &
    MITM_PID=$!
    sleep 2

    echo "Sending HTTPS request through proxy..."
    curl -x http://127.0.0.1:8083 -s https://example.com > /dev/null 2>&1 || true

    sleep 2
    kill $MITM_PID 2>/dev/null || true
    wait $MITM_PID 2>/dev/null || true

    echo "Test completed"

} > "$RESULTS_DIR/06_ssl_strip_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/06_ssl_strip_$TIMESTAMP.log${NC}"
echo ""

# Test 7: Replay Attack Capture
echo -e "${BLUE}[7/8] Testing Replay Attack Detection...${NC}"
{
    echo "=== Replay Attack Test ==="
    echo "Capturing traffic for replay..."
    echo ""

    timeout 10s mitmdump -s "$SCRIPT_DIR/replay_attack.py" -p 8084 --ssl-insecure 2>&1 &
    MITM_PID=$!
    sleep 2

    # Send multiple requests
    for i in {1..3}; do
        echo "Request $i..."
        curl -x http://127.0.0.1:8084 -s http://example.com > /dev/null 2>&1 || true
        sleep 1
    done

    sleep 2
    kill $MITM_PID 2>/dev/null || true
    wait $MITM_PID 2>/dev/null || true

    echo "Test completed"

} > "$RESULTS_DIR/07_replay_attack_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/07_replay_attack_$TIMESTAMP.log${NC}"
echo ""

# Test 8: Fuzzing
echo -e "${BLUE}[8/8] Testing Input Fuzzing...${NC}"
{
    echo "=== Fuzzing Test ==="
    echo ""

    echo "Fuzzing with random data..."
    for i in {1..10}; do
        echo "Fuzz test $i"
        dd if=/dev/urandom bs=1024 count=1 2>/dev/null | \
            curl -s -X POST http://127.0.0.1:8787/status --data-binary @- || true
    done

    echo ""
    echo "Fuzzing with format strings..."
    curl -s -X POST http://127.0.0.1:8787/status -d "%s%s%s%s%s%s" || true
    curl -s -X POST http://127.0.0.1:8787/status -d "%x%x%x%x%x%x" || true

    echo ""
    echo "Fuzzing with special characters..."
    curl -s -X POST http://127.0.0.1:8787/status -d "\x00\x01\x02\x03" || true
    curl -s -X POST http://127.0.0.1:8787/status -d "../../etc/passwd" || true

    echo ""
    echo "Test completed"

} > "$RESULTS_DIR/08_fuzzing_$TIMESTAMP.log" 2>&1
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/08_fuzzing_$TIMESTAMP.log${NC}"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Suite Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Results saved to: ${GREEN}$RESULTS_DIR${NC}"
echo ""
echo "Review the logs for detailed results:"
ls -lh "$RESULTS_DIR"/*_$TIMESTAMP.log
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Review all log files in $RESULTS_DIR"
echo "2. Check for any unexpected errors or crashes"
echo "3. Verify HSIP properly rejected all attack attempts"
echo "4. Run UDP protocol tests with hsip-cli commands"
echo ""
echo -e "${GREEN}Security testing complete!${NC}"
