# EmbeddedML - Lightweight ML framework for FPU-less embedded systems

CC ?= gcc
MIPS_CC ?= mipsel-openwrt-linux-musl-gcc
ARM_CC ?= arm-linux-gnueabi-gcc

CFLAGS = -O2 -Wall -Wextra
MIPS32_CFLAGS := -I${TARGET_DIR}/usr/include 

LDFLAGS_PCAP = -lpcap -lm
MIPS32_LDFLAGS := -L${TARGET_DIR}/usr/lib -lpcap -static

SRC = src
BIN = bin
EXAMPLES = examples

.PHONY: all native mips arm clean help test

all: native

native: $(BIN)/cicflowmeter $(BIN)/ids

$(BIN)/cicflowmeter: $(SRC)/cicflowmeter/cicflowmeter.c
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS_PCAP)

$(BIN)/ids: $(EXAMPLES)/ids/model.c
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# MIPS32 soft-float (OpenWRT routers: TP-Link, GL.iNet, etc.)
mips: $(BIN)/ids-mips $(BIN)/cicflowmeter-mips
$(BIN)/ids-mips: $(EXAMPLES)/ids/model.c
	@mkdir -p $(BIN)
	$(MIPS_CC) -static $(MIPS32_CFLAGS) -o $@ $<
	@echo "Verifying soft-float..."
	@! objdump -d $@ 2>/dev/null | grep -qE '\s(lwc1|swc1|add\.s|mul\.s)' && echo "OK: No FPU ops"

$(BIN)/cicflowmeter-mips: $(SRC)/cicflowmeter/cicflowmeter.c
	@mkdir -p $(BIN)
	$(MIPS_CC) $(MIPS32_CFLAGS) -o $@ $< $(MIPS32_LDFLAGS)

# ARM soft-float
arm: $(BIN)/ids-arm
$(BIN)/ids-arm: $(EXAMPLES)/ids/model.c
	@mkdir -p $(BIN)
	$(ARM_CC) -static $(CFLAGS) -mfloat-abi=soft -o $@ $<

clean:
	rm -rf $(BIN)

test: native
	@echo "Test: benign traffic"
	./$(BIN)/ids $(EXAMPLES)/ids/test_data/benign.csv 50
	@echo "Test: attack traffic"
	./$(BIN)/ids $(EXAMPLES)/ids/test_data/syn_flood.csv 10

help:
	@echo "EmbeddedML - ML for resource-constrained devices"
	@echo ""
	@echo "Targets:"
	@echo "  native  - Build for host (default)"
	@echo "  mips    - Build for MIPS32 soft-float"
	@echo "  arm     - Build for ARM soft-float"
	@echo "  test    - Run basic tests"
	@echo "  clean   - Remove binaries"
	@echo ""
	@echo "Cross-compile:"
	@echo "  make mips MIPS_CC=/path/to/mipsel-gcc"
