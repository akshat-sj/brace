#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE=${SCRIPT_DIR}/openwrt-sdk-24.10.0-malta-le_gcc-13.3.0_musl.Linux-x86_64

export STAGING_DIR=${BASE}/staging_dir
export TOOLCHAIN_DIR=$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl
export TARGET_DIR=$STAGING_DIR/target-mipsel_24kc_musl
export PATH=$TOOLCHAIN_DIR/bin:$PATH
