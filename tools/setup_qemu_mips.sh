#!/bin/bash
#
# QEMU MIPS32 Setup and Benchmark Script
# For MIPS-ML IDS Project

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
SDK="openwrt-sdk-${OPENWRT_VERSION}-malta-le_gcc-13.3.0_musl.Linux-x86_64.tar.zst"

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
    log_info "Downloading rootfs image..."
    wget -q --show-progress "${OPENWRT_BASE_URL}/${ROOTFS_GZ}"

    # Extract
    log_info "Extracting rootfs..."
    gunzip -k "$ROOTFS_GZ"
    rm -f "$ROOTFS_GZ"

    # Download kernel
    if [ ! -f "$KERNEL" ]; then
        log_info "Downloading kernel..."
        wget -q --show-progress "${OPENWRT_BASE_URL}/${KERNEL}"
    else
        log_success "Kernel already exists"
    fi

    log_success "OpenWRT files ready"
}

# ============================================================
# Get Cross-Compiler
# ============================================================

get_cross_compiler() {
    log_info "Downloading SDK files..."
    [ "$EUID" -ne 0 ] && { echo "Run as root (sudo)"; exit 1; }
    cd "$SCRIPT_DIR"

    # Download SDK
    if [ ! -f "$SDK" ]; then
        log_info "Downloading SDK..."
        wget -q --show-progress "${OPENWRT_BASE_URL}/${SDK}"
    fi

    tar -I zstd -xf "$SDK"
    cd openwrt-sdk-24.10.0-malta-le_gcc-13.3.0_musl.Linux-x86_64

    # Add libpcap To Cross-Compiler
    ./scripts/feeds update -a
    ./scripts/feeds install -a

    echo "CONFIG_PACKAGE_libpcap=y" >> .config
    make defconfig
    make package/libpcap/compile V=s

    log_success "SDK files ready"
}

# ============================================================
# QEMU Functions
# ============================================================

config_qemu(){
    log_info "Configuring QEMU MIPS32..."
    cd "$SCRIPT_DIR"

    MNT="boot_mnt"
    mkdir -p "$MNT"

    sudo mount -o loop "$ROOTFS_IMG" "$MNT"
    sudo tee ${MNT}/etc/uci-defaults/99-firstboot-setup > /dev/null <<'EOF'
#!/bin/sh

uci set network.lan.proto='dhcp'
uci set network.lan.device='eth0'
uci set network.lan.ifname='eth0'
uci commit network

/etc/init.d/network restart
/etc/init.d/dropbear enable
/etc/init.d/dropbear start

EOF

    sudo chmod +x "$MNT/etc/uci-defaults/99-firstboot-setup"
    sync
    sudo umount "$MNT"

    log_success "Image configured successfully."

}

start_qemu() {
    log_info "Starting QEMU MIPS32..."
    cd "$SCRIPT_DIR"

    if [ ! -f "$ROOTFS_IMG" ] || [ ! -f "$KERNEL" ]; then
        log_error "OpenWRT files not found. Run: $0 download"
        exit 1
    fi

    [ "$EUID" -ne 0 ] && { echo "Run as root (sudo)"; exit 1; }
    config_qemu

    qemu-system-mipsel -M malta \
        -hda "$ROOTFS_IMG" \
        -kernel "$KERNEL" \
        -nographic \
        -append "root=/dev/sda console=ttyS0" \
        -net nic -net user,hostfwd=tcp::2222-:22 \
        -m 128

    
}

start_qemu_background() { # i did not test, make it call config to make it work
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

stop_qemu() { # i did not test
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
    cd ${SCRIPT_DIR}
    log_info "Copying binaries to QEMU..."

    local SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    local SCP="scp -P 2222 $SSH_OPTS"
    local SSH="ssh -p 2222 $SSH_OPTS root@localhost"

    # Create directory
    $SSH "mkdir -p /tmp/benchmark" 2>/dev/null

    # Copy MIPS binaries
    if [ -f "../bin/ids-mips" ]; then
        $SCP ../bin/ids-mips root@localhost:/tmp/benchmark/
        log_success "Copied model_integer_mips"
    fi

    if [ -f "../bin/cicflowmeter-mips" ]; then
        $SCP ../bin/cicflowmeter-mips root@localhost:/tmp/benchmark/
        log_success "Copied capture"
    fi

    # Copy test data
    local TEST_CSV="../examples/ids/test_data/syn_flood.csv"
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

run_benchmark() { # didnt test it, files not found 
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

full_benchmark() { # didnt test it, files not found 
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
    get_cc)
        get_cross_compiler
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
