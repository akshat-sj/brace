#!/bin/bash
# Performance Measurement for MIPS-ML NIDS
# Paper Reference: Section V-C (Resource Overhead)
#
# Measures:
# - Memory usage (VmRSS, RssAnon, Stack)
# - Inference latency
# - CPU utilization

set -e

CAPTURE_BIN="${CAPTURE_BIN:-./Bin/capture}"
MODEL_BIN="${MODEL_BIN:-./Bin/model}"
TEST_CSV="${TEST_CSV:-test_flows.csv}"
OUTPUT_DIR="${OUTPUT_DIR:-./perf_results}"

mkdir -p "$OUTPUT_DIR"

echo "=== MIPS-ML Performance Measurement ==="
echo "Date: $(date)"
echo ""

# 1. Memory Measurement

measure_memory() {
    local pid=$1
    local name=$2

    echo "[$name] Memory Usage:"

    # Read from /proc/self/status
    if [ -f "/proc/$pid/status" ]; then
        local vmrss=$(grep VmRSS /proc/$pid/status | awk '{print $2}')
        local vmhwm=$(grep VmHWM /proc/$pid/status | awk '{print $2}')
        local vmstk=$(grep VmStk /proc/$pid/status | awk '{print $2}')
        local rssanon=$(grep RssAnon /proc/$pid/status | awk '{print $2}')

        echo "  VmRSS (Current):     ${vmrss:-N/A} KB"
        echo "  VmHWM (Peak):        ${vmhwm:-N/A} KB"
        echo "  VmStk (Stack):       ${vmstk:-N/A} KB"
        echo "  RssAnon (Heap):      ${rssanon:-N/A} KB"

        # Save to file
        cat /proc/$pid/status > "$OUTPUT_DIR/${name}_status.txt"
    fi

    # Using time -v for detailed stats
    echo ""
}

# 2. Inference Latency

measure_latency() {
    echo "[Inference] Latency Measurement:"

    if [ ! -f "$MODEL_BIN" ]; then
        echo "  Error: Model binary not found at $MODEL_BIN"
        return 1
    fi

    if [ ! -f "$TEST_CSV" ]; then
        echo "  Error: Test CSV not found at $TEST_CSV"
        return 1
    fi

    # Run inference multiple times and measure
    local iterations=100
    local total_time=0

    echo "  Running $iterations iterations..."

    for i in $(seq 1 $iterations); do
        local start=$(date +%s%N)
        $MODEL_BIN "$TEST_CSV" > /dev/null 2>&1
        local end=$(date +%s%N)
        local elapsed=$(( (end - start) / 1000000 ))  # Convert to ms
        total_time=$((total_time + elapsed))
    done

    local avg_time=$((total_time / iterations))
    echo "  Average latency: ${avg_time} ms per batch"
    echo "  Total time: ${total_time} ms for $iterations iterations"

    # Save results
    echo "iterations,$iterations" > "$OUTPUT_DIR/latency.csv"
    echo "total_ms,$total_time" >> "$OUTPUT_DIR/latency.csv"
    echo "avg_ms,$avg_time" >> "$OUTPUT_DIR/latency.csv"
}


# 3. CPU Utilization

measure_cpu() {
    local pid=$1
    local name=$2
    local duration=${3:-10}

    echo "[$name] CPU Utilization (${duration}s sample):"

    if command -v pidstat &> /dev/null; then
        pidstat -p $pid 1 $duration | tee "$OUTPUT_DIR/${name}_cpu.txt"
    else
        # Fallback: manual /proc/stat parsing
        local cpu_start=$(cat /proc/$pid/stat | awk '{print $14+$15}')
        sleep $duration
        local cpu_end=$(cat /proc/$pid/stat | awk '{print $14+$15}')
        local cpu_ticks=$((cpu_end - cpu_start))
        local hz=$(getconf CLK_TCK)
        local cpu_percent=$((cpu_ticks * 100 / hz / duration))
        echo "  CPU Usage: ~${cpu_percent}%"
    fi
}

# 4. Full System Benchmark

run_full_benchmark() {
    echo "[Full System] Running complete benchmark..."

    # Start capture in background
    $CAPTURE_BIN eth0 &
    local capture_pid=$!
    sleep 2

    # Measure capture memory
    measure_memory $capture_pid "capture"

    # Generate some traffic
    echo "  Generating test traffic..."
    ping -c 100 -i 0.01 localhost > /dev/null 2>&1 &

    # Measure CPU during operation
    measure_cpu $capture_pid "capture" 10

    # Stop capture
    kill $capture_pid 2>/dev/null || true

    # Measure inference latency
    measure_latency

    echo ""
    echo "Benchmark complete. Results in: $OUTPUT_DIR"
}


# 5. QEMU Performance Test

qemu_benchmark() {
    echo "[QEMU] Running benchmark in emulated MIPS32..."

    # Check if running in QEMU
    if grep -q "MIPS" /proc/cpuinfo 2>/dev/null; then
        echo "  Detected MIPS architecture"
        cat /proc/cpuinfo | head -20

        # Memory info
        echo ""
        echo "  System Memory:"
        free -h

        # Run standard benchmarks
        run_full_benchmark
    else
        echo "  Not running on MIPS - use QEMU to emulate"
        echo "  See README.md for QEMU setup instructions"
    fi
}


# Summary Output

generate_summary() {
    echo ""
    echo "=== Performance Summary ==="
    echo ""

    # From paper Section V-C targets
    echo "Paper Targets vs Measured:"
    echo "  Memory (VmRSS):     < 640 KB"
    echo "  Heap (RssAnon):     = 0 KB (no dynamic allocation)"
    echo "  Stack:              < 132 KB"
    echo "  Inference Latency:  ~10 ms/flow"
    echo "  CPU Utilization:    ~87% (burst)"
    echo ""

    if [ -f "$OUTPUT_DIR/latency.csv" ]; then
        local measured_latency=$(grep avg_ms "$OUTPUT_DIR/latency.csv" | cut -d, -f2)
        echo "Measured Latency: ${measured_latency} ms"
    fi
}


# Main

case "${1:-help}" in
    memory)
        if [ -z "$2" ]; then
            echo "Usage: $0 memory <pid>"
            exit 1
        fi
        measure_memory "$2" "process"
        ;;
    latency)
        measure_latency
        ;;
    cpu)
        if [ -z "$2" ]; then
            echo "Usage: $0 cpu <pid> [duration_sec]"
            exit 1
        fi
        measure_cpu "$2" "process" "${3:-10}"
        ;;
    full)
        run_full_benchmark
        generate_summary
        ;;
    qemu)
        qemu_benchmark
        ;;
    summary)
        generate_summary
        ;;
    *)
        echo "Usage: $0 {memory|latency|cpu|full|qemu|summary}"
        echo ""
        echo "Commands:"
        echo "  memory <pid>      - Measure memory usage of process"
        echo "  latency           - Measure inference latency"
        echo "  cpu <pid> [sec]   - Measure CPU utilization"
        echo "  full              - Run complete benchmark"
        echo "  qemu              - Benchmark in QEMU MIPS32"
        echo "  summary           - Show performance summary"
        exit 1
        ;;
esac