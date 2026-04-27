# BRACE

An execution framework for deploying ML-based network analytics on embedded routers without floating-point hardware, high-level runtimes, or centralized processing.

## Quick Start

```bash
# Build
make

# Extract flow features from pcap
./bin/cicflowmeter -f traffic.pcap -o flows.csv

# Classify flows
./bin/ids flows.csv 10
```

## Feature Extraction

C implementation of CICFlowMeter. Outputs 82 flow features compatible with CIC-IDS datasets.

```bash
# From pcap file
./bin/cicflowmeter -f capture.pcap -o flows.csv

# Live capture (Ctrl+C to stop)
sudo ./bin/cicflowmeter -i eth0 -o flows.csv

# Verbose output
./bin/cicflowmeter -f capture.pcap -o flows.csv -v
```

## Classification

Integer-only ML inference. No FPU required.

```bash
# Classify with 10% threshold (more sensitive)
./bin/ids flows.csv 10

# Classify with 50% threshold (default)
./bin/ids flows.csv

# Output
# [ALERT] Flow 1: MALICIOUS (score=169132/655360)
# === Results ===
# Total: 99
# Malicious: 98 (98%)
# Benign: 1 (1%)
```

## Building

### Native

```bash
make              # Build all
make clean        # Clean
```

### Cross-Compilation

```bash
# MIPS32 (OpenWRT routers)
make mips MIPS_CC=mipsel-openwrt-linux-musl-gcc

# ARM (soft-float)
make arm ARM_CC=arm-linux-gnueabi-gcc
```

### Verify Soft-Float

```bash
# Should output nothing (no FPU instructions)
objdump -d bin/ids-mips | grep -E 'lwc1|swc1|add\.s|mul\.s'

# Check ABI
readelf -A bin/ids-mips | grep "FP ABI"
```
## Run on Qemu

```bash
./tools/setup_qemu_mips.sh download
sudo ./tools/setup_qemu_mips.sh get_cc

source ./tools/setup_env.sh
make mips

sudo ./tools/setup_qemu_mips.sh start
./tools/setup_qemu_mips.sh copy

```


## Training Your Own Model

```bash
# 1. Train in scikit-learn
python tools/train_model.py

# 2. Convert to integer C
python tools/convert_to_integer.py tl2cgen_output.c model.c

# 3. Build
make
```

## Project Structure

```
src/
├── cicflowmeter/      # Flow feature extraction
└── integerml/         # Integer ML headers

tools/
├── train_model.py     # Model training
├── convert_to_integer.py
└── setup_qemu_mips.sh

examples/
└── ids/               # IDS example
    ├── model.c
    ├── test_data/
    └── pcaps/

dataset/               # CIC-IDS2018 data
```


## Tested Platforms

| Platform | Device | Status |
|----------|--------|--------|
| MIPS32 | TP-Link Archer (OpenWRT) | Validated |
| MIPS32 | QEMU Malta | Validated |
| ARM | QEMU (soft-float) | Validated |
| x86_64 | Native Linux | Validated |
