#!/bin/bash
#
# QEMU MIPS32 Setup and Benchmark Script
# For MIPS-ML NIDS Project
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENWRT_VERSION="24.10.0"
OPENWRT_BASE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/malta/le"

# File names
ROOTFS_GZ="openwrt-${OPENWRT_VERSION}-malta-le-rootfs-ext4.img.gz"
ROOTFS_IMG="openwrt-${OPENWRT_VERSION}-malta-le-rootfs-ext4.img"
KERNEL="openwrt-${OPENWRT_VERSION}-malta-le-vmlinux.elf"
TOOLCHAIN="openwrt-toolchain-${OPENWRT_VERSION}-malta-le_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
EXTRA_STORAGE="extra_storage.img"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================
# Download Functions
# ============================================================

download_openwrt() {
    log_info "Downloading OpenWRT files..."
    cd "$SCRIPT_DIR"

    # Download rootfs
    if [ ! -f "$ROOTFS_IMG" ]; then
        if [ ! -f "$ROOTFS_GZ" ]; then
            log_info "Downloading rootfs image..."
            wget -q --show-progress "${OPENWRT_BASE_URL}/${ROOTFS_GZ}"
        fi
        log_info "Extracting rootfs..."
        gunzip -k "$ROOTFS_GZ"
    else
        log_success "Rootfs already exists"
    fi

    # Download kernel
    if [ ! -f "$KERNEL" ]; then
        log_info "Downloading kernel..."
        wget -q --show-progress "${OPENWRT_BASE_URL}/${KERNEL}"
    else
        log_success "Kernel already exists"
    fi

    # Create extra storage
    if [ ! -f "$EXTRA_STORAGE" ]; then
        log_info "Creating extra storage disk (512MB)..."
        qemu-img create -f raw "$EXTRA_STORAGE" 512M
    else
        log_success "Extra storage already exists"
    fi

    log_success "OpenWRT files ready"
}

download_toolchain() {
    log_info "Downloading MIPS toolchain..."
    cd "$SCRIPT_DIR"

    if [ ! -f "$TOOLCHAIN" ]; then
        log_info "Downloading toolchain (~44MB)..."
        wget -q --show-progress "${OPENWRT_BASE_URL}/${TOOLCHAIN}"
    fi

    if [ ! -d "toolchain" ]; then
        log_info "Extracting toolchain..."
        mkdir -p toolchain
        tar -I zstd -xf "$TOOLCHAIN" -C toolchain --strip-components=1
    fi

    log_success "Toolchain ready at $SCRIPT_DIR/toolchain"
}

# ============================================================
# Cross-Compilation
# ============================================================

cross_compile() {
    log_info "Cross-compiling for MIPS32..."
    cd "$SCRIPT_DIR"

    # Find the cross-compiler
    local CC=""
    local TOOLCHAIN_BIN="$SCRIPT_DIR/toolchain/bin"

    if [ -d "$TOOLCHAIN_BIN" ]; then
        CC=$(find "$TOOLCHAIN_BIN" -name "*-gcc" | head -1)
    fi

    if [ -z "$CC" ] || [ ! -x "$CC" ]; then
        # Try system cross-compiler
        if command -v mipsel-linux-gnu-gcc-11 &> /dev/null; then
            CC="mipsel-linux-gnu-gcc-11"
        elif command -v mipsel-linux-gnu-gcc &> /dev/null; then
            CC="mipsel-linux-gnu-gcc"
        else
            log_error "No MIPS cross-compiler found!"
            log_info "Install with: sudo apt install gcc-11-mipsel-linux-gnu"
            log_info "Or run: $0 toolchain"
            return 1
        fi
    fi

    log_info "Using compiler: $CC"

    # Compile model_integer.c (pure C, no dependencies)
    if [ -f "model_integer.c" ]; then
        log_info "Compiling model_integer.c..."
        # Try with soft-float first, fall back to hard-float if not available
        # (code is integer-only so no FPU instructions generated anyway)
        if $CC -static -O2 -msoft-float model_integer.c -o Bin/model_integer_mips -DMIPS32_BUILD 2>/dev/null; then
            log_success "Compiled with soft-float"
        else
            log_warn "Soft-float libs not available, compiling with hard-float"
            $CC -static -O2 model_integer.c -o Bin/model_integer_mips -DMIPS32_BUILD
        fi
        log_success "Created Bin/model_integer_mips"
        file Bin/model_integer_mips

        # Verify no FPU instructions (integer-only code)
        log_info "Checking for FPU instructions..."
        if mipsel-linux-gnu-objdump -d Bin/model_integer_mips 2>/dev/null | grep -qE '\s(lwc1|swc1|add\.s|mul\.s|div\.s|cvt\.)'; then
            log_warn "Warning: FPU instructions detected!"
        else
            log_success "No FPU instructions - safe for soft-float MIPS"
        fi
    fi

    # Compile capture_stream.c (needs libpcap - static build)
    if [ -f "capture_stream.c" ]; then
        log_warn "capture_stream.c requires libpcap for MIPS"
        log_info "For now, use the pre-compiled 'capture' binary or build in QEMU"
    fi

    log_success "Cross-compilation complete"
}

# ============================================================
# QEMU Functions
# ============================================================

start_qemu() {
    log_info "Starting QEMU MIPS32..."
    cd "$SCRIPT_DIR"

    if [ ! -f "$ROOTFS_IMG" ] || [ ! -f "$KERNEL" ]; then
        log_error "OpenWRT files not found. Run: $0 download"
        exit 1
    fi

    log_info "QEMU will start. Login as 'root' (no password)"
    log_info "SSH available at localhost:2222"
    log_info "Press Ctrl+A then X to exit QEMU"
    echo ""

    qemu-system-mipsel -M malta \
        -hda "$ROOTFS_IMG" \
        -kernel "$KERNEL" \
        -nographic \
        -append "root=/dev/sda console=ttyS0" \
        -net nic -net user,hostfwd=tcp::2222-:22 \
        -drive file="$EXTRA_STORAGE",format=raw \
        -m 128
}

start_qemu_background() {
    log_info "Starting QEMU in background..."
    cd "$SCRIPT_DIR"

    if [ ! -f "$ROOTFS_IMG" ] || [ ! -f "$KERNEL" ]; then
        log_error "OpenWRT files not found. Run: $0 download"
        exit 1
    fi

    # Check if already running
    if pgrep -f "qemu-system-mipsel.*malta" > /dev/null; then
        log_warn "QEMU already running"
        return 0
    fi

    # Run QEMU in background with output to file
    nohup qemu-system-mipsel -M malta \
        -hda "$ROOTFS_IMG" \
        -kernel "$KERNEL" \
        -nographic \
        -append "root=/dev/sda console=ttyS0" \
        -net nic -net user,hostfwd=tcp::2222-:22 \
        -drive file="$EXTRA_STORAGE",format=raw \
        -m 128 \
        > /tmp/qemu-mips.log 2>&1 &

    echo $! > /tmp/qemu-mips.pid
    log_info "QEMU PID: $(cat /tmp/qemu-mips.pid)"

    log_info "Waiting for QEMU to boot (this takes ~30-60 seconds)..."
    sleep 20

    # Wait for SSH
    for i in {1..30}; do
        if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@localhost "echo ok" 2>/dev/null; then
            log_success "QEMU ready! SSH available at localhost:2222"
            return 0
        fi
        log_info "Waiting for SSH... ($i/30)"
        sleep 3
    done

    log_error "QEMU failed to start SSH. Check /tmp/qemu-mips.log"
    return 1
}

stop_qemu() {
    log_info "Stopping QEMU..."
    if [ -f /tmp/qemu-mips.pid ]; then
        kill $(cat /tmp/qemu-mips.pid) 2>/dev/null || true
        rm -f /tmp/qemu-mips.pid
    fi
    pkill -f "qemu-system-mipsel.*malta" 2>/dev/null || true
    log_success "QEMU stopped"
}

# ============================================================
# Benchmark Functions
# ============================================================

copy_to_qemu() {
    log_info "Copying binaries to QEMU..."

    local SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    local SCP="scp -P 2222 $SSH_OPTS"
    local SSH="ssh -p 2222 $SSH_OPTS root@localhost"

    # Create directory
    $SSH "mkdir -p /tmp/benchmark" 2>/dev/null

    # Copy MIPS binaries
    if [ -f "Bin/model_integer_mips" ]; then
        $SCP Bin/model_integer_mips root@localhost:/tmp/benchmark/
        log_success "Copied model_integer_mips"
    fi

    if [ -f "Bin/capture" ]; then
        $SCP Bin/capture root@localhost:/tmp/benchmark/
        log_success "Copied capture"
    fi

    if [ -f "Bin/model" ]; then
        $SCP Bin/model root@localhost:/tmp/benchmark/
        log_success "Copied model"
    fi

    # Copy test data
    local TEST_CSV="../real_attack_pcaps/dos_syn_flood_model.csv"
    if [ -f "$TEST_CSV" ]; then
        $SCP "$TEST_CSV" root@localhost:/tmp/benchmark/test_data.csv
        log_success "Copied test data"
    else
        log_warn "No test CSV found at $TEST_CSV"
        log_info "Creating minimal test data..."
        # Create a small test CSV with sample data
        cat > /tmp/test_data.csv << 'EOF'
Dst Port,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd Header Len,Bwd Header Len
8080,1000000,100,50,5000,2500,100,20,50,25,80,10,50,20,5000000,100000,10000,5000,50000,100,900000,9000,4500,45000,90,450000,9000,4500,45000,90,1,0,2000,1000
EOF
        $SCP /tmp/test_data.csv root@localhost:/tmp/benchmark/
    fi
}

run_benchmark() {
    log_info "Running benchmarks on MIPS32..."

    local SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    local SSH="ssh -p 2222 $SSH_OPTS root@localhost"

    echo ""
    echo "=============================================="
    echo "         MIPS32 BENCHMARK RESULTS"
    echo "=============================================="
    echo ""

    # System info
    log_info "System Information:"
    $SSH "cat /proc/cpuinfo | grep -E '(system type|cpu model|BogoMIPS)'"
    echo ""

    # Memory before
    log_info "Memory (before):"
    $SSH "free -m"
    echo ""

    # Check binaries
    log_info "Checking binaries..."
    $SSH "ls -lh /tmp/benchmark/"
    echo ""

    # Benchmark model_integer_mips
    if $SSH "test -f /tmp/benchmark/model_integer_mips"; then
        log_info "Benchmarking model_integer_mips..."
        $SSH "chmod +x /tmp/benchmark/model_integer_mips"

        # Time the execution
        echo "Running classification (10 iterations)..."
        $SSH "cd /tmp/benchmark && time for i in 1 2 3 4 5 6 7 8 9 10; do ./model_integer_mips test_data.csv 0.10 > /dev/null; done" 2>&1

        # Single run with output
        echo ""
        log_info "Classification output:"
        $SSH "cd /tmp/benchmark && ./model_integer_mips test_data.csv 0.10"

        # Memory usage
        echo ""
        log_info "Memory usage during execution:"
        $SSH "cd /tmp/benchmark && ./model_integer_mips test_data.csv 0.10 & PID=\$!; sleep 0.5; cat /proc/\$PID/status 2>/dev/null | grep -E '(VmRSS|VmPeak|VmSize)' || echo 'Process too fast to measure'; wait"
    fi

    echo ""
    # Memory after
    log_info "Memory (after):"
    $SSH "free -m"

    echo ""
    echo "=============================================="
    log_success "Benchmark complete!"
}

full_benchmark() {
    log_info "Running full benchmark suite..."

    # Ensure QEMU is running
    if ! pgrep -f "qemu-system-mipsel.*malta" > /dev/null; then
        start_qemu_background
    fi

    # Copy files and run benchmarks
    copy_to_qemu
    run_benchmark
}

# ============================================================
# Main
# ============================================================

usage() {
    echo "QEMU MIPS32 Setup and Benchmark Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  download    - Download OpenWRT images for QEMU"
    echo "  toolchain   - Download MIPS cross-compilation toolchain"
    echo "  compile     - Cross-compile code for MIPS32"
    echo "  start       - Start QEMU (interactive)"
    echo "  startbg     - Start QEMU in background"
    echo "  stop        - Stop QEMU"
    echo "  copy        - Copy binaries to QEMU"
    echo "  benchmark   - Run benchmarks on QEMU"
    echo "  full        - Full setup: download, compile, start, benchmark"
    echo "  ssh         - SSH into QEMU"
    echo ""
    echo "Examples:"
    echo "  $0 download              # Download OpenWRT files"
    echo "  $0 compile               # Cross-compile for MIPS32"
    echo "  $0 start                 # Start QEMU interactively"
    echo "  $0 full                  # Do everything"
}

case "${1:-}" in
    download)
        download_openwrt
        ;;
    toolchain)
        download_toolchain
        ;;
    compile)
        cross_compile
        ;;
    start)
        start_qemu
        ;;
    startbg)
        start_qemu_background
        ;;
    stop)
        stop_qemu
        ;;
    copy)
        copy_to_qemu
        ;;
    benchmark)
        run_benchmark
        ;;
    full)
        download_openwrt
        cross_compile
        start_qemu_background
        copy_to_qemu
        run_benchmark
        ;;
    ssh)
        ssh -o StrictHostKeyChecking=no -p 2222 root@localhost
        ;;
    *)
        usage
        exit 1
        ;;
esac
