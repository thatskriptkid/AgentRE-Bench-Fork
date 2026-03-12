#!/usr/bin/env bash
#
# build_win_binaries.sh — Cross-compile 12 C samples from samples/ to Windows PE (x86-64).
#
# Uses the same sources as build_binaries.sh; #ifdef _WIN32 selects Windows code.
# Requires MinGW-w64: apt install mingw-w64 (x86_64-w64-mingw32-gcc).
# On Linux Mint: sudo apt install mingw-w64
# If MinGW is not available, uses Docker with Ubuntu + mingw-w64.
#
# Output: binaries_pe/level1.exe … level12.exe
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="$SCRIPT_DIR/samples"
BINARIES_DIR="$SCRIPT_DIR/binaries_pe"
DOCKER_IMAGE="ubuntu:22.04"

CFLAGS="-O0 -Wall"
# Link Winsock for Windows builds (sources use #pragma comment(lib) but explicit link is safe)
LDFLAGS="-lws2_32"

mkdir -p "$BINARIES_DIR"

# Source file (may have spaces) → output .exe name (12 levels only)
build_list=(
    "level1_TCPServer.c:level1.exe"
    "level2_XorEncodedStrings.c:level2.exe"
    "level3_anti-debugging_reverseShell.c:level3.exe"
    "level4_polymorphicReverseShell.c:level4.exe"
    "level5_MultistageReverseShell.c:level5.exe"
    "level6_ICMP Covert Channel Shell.c:level6.exe"
    "level7_DNS_TunnelReverse Shell.c:level7.exe"
    "level8_Process_hollowing_reverse_shell.c:level8.exe"
    "level9_SharedObjectInjectionReverseShell.c:level9.exe"
    "level10_fully_obfuscated_AES_Encrypted Shell.c:level10.exe"
    "level11_ForkBombReverseShell.c:level11.exe"
    "level12_JIT_Compiled_Shellcode.c:level12.exe"
)

USE_DOCKER=true
if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
    USE_DOCKER=false
elif ! command -v docker &>/dev/null; then
    echo "Error: Neither x86_64-w64-mingw32-gcc nor docker found." >&2
    echo "On Linux Mint: sudo apt install mingw-w64" >&2
    exit 1
fi

echo "=== AgentRE-Bench: Building Windows PE from samples/ ==="
echo "Samples dir:  $SAMPLES_DIR"
echo "Output dir:   $BINARIES_DIR"
if [ "$USE_DOCKER" = true ]; then
    echo "Build mode:   Docker ($DOCKER_IMAGE + mingw-w64)"
else
    echo "Build mode:   Local MinGW ($(x86_64-w64-mingw32-gcc --version | head -1))"
fi
echo ""

SUCCESS=0
FAIL=0

build_one() {
    local src_name="$1"
    local out_name="$2"
    local src_path="$SAMPLES_DIR/$src_name"
    if [ ! -f "$src_path" ]; then
        echo "Building $out_name ... SKIP (source not found)"
        return 1
    fi
    echo -n "Building $out_name ... "
    if x86_64-w64-mingw32-gcc $CFLAGS -o "$BINARIES_DIR/$out_name" "$src_path" $LDFLAGS 2>&1; then
        echo "OK"
        return 0
    else
        echo "FAILED"
        return 1
    fi
}

if [ "$USE_DOCKER" = true ]; then
    echo "Installing mingw-w64 in container (one-time), then building 12 PE binaries ..."
    if docker run --rm --platform linux/amd64 \
        -v "$SAMPLES_DIR:/src:ro" \
        -v "$BINARIES_DIR:/out" \
        -w /src \
        "$DOCKER_IMAGE" \
        bash -c '
            apt-get update -qq && apt-get install -y -qq mingw-w64 >/dev/null
            S=0 F=0
            compile() { if x86_64-w64-mingw32-gcc -O0 -Wall -o "/out/$2" "/src/$1" -lws2_32 2>/dev/null; then echo "Building $2 ... OK"; S=$((S+1)); else echo "Building $2 ... FAILED"; F=$((F+1)); fi; }
            compile "level1_TCPServer.c" "level1.exe"
            compile "level2_XorEncodedStrings.c" "level2.exe"
            compile "level3_anti-debugging_reverseShell.c" "level3.exe"
            compile "level4_polymorphicReverseShell.c" "level4.exe"
            compile "level5_MultistageReverseShell.c" "level5.exe"
            compile "level6_ICMP Covert Channel Shell.c" "level6.exe"
            compile "level7_DNS_TunnelReverse Shell.c" "level7.exe"
            compile "level8_Process_hollowing_reverse_shell.c" "level8.exe"
            compile "level9_SharedObjectInjectionReverseShell.c" "level9.exe"
            compile "level10_fully_obfuscated_AES_Encrypted Shell.c" "level10.exe"
            compile "level11_ForkBombReverseShell.c" "level11.exe"
            compile "level12_JIT_Compiled_Shellcode.c" "level12.exe"
            echo ""; echo "=== Build complete: $S succeeded, $F failed ==="
            exit $F
        '; then
        SUCCESS=12
        FAIL=0
    else
        echo "Some builds failed (see above)."
        exit 1
    fi
else
    for entry in "${build_list[@]}"; do
        src_name="${entry%%:*}"
        out_name="${entry##*:}"
        if build_one "$src_name" "$out_name"; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAIL=$((FAIL + 1))
        fi
    done
fi

echo ""
echo "=== Build complete: $SUCCESS succeeded, $FAIL failed ==="
echo "Binaries in: $BINARIES_DIR"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
