#!/usr/bin/env bash
#
# mayhem/build.sh — build osslsigncode's fuzz harnesses (sanitized) and its functional test suite
# (normal flags). Runs in the commit image as `mayhem` in /mayhem; re-runnable and offline.
#   build/fuzz    sanitized + SanCov-instrumented project (CLI and the objects the harnesses link)
#   build/normal  Release build, with upstream's ctest suite configured (needs python3-cryptography)
# Both live under build/, which upstream's .gitignore covers, so `git clean -ffdX` removes them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) The project, sanitized, with SanCov on the library code (fuzzer-no-link) and DWARF <= 3.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S . -B build/fuzz -G Ninja \
    -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS"
cmake --build build/fuzz -j"$MAYHEM_JOBS"

# 2) Harnesses. fuzz_osslsigncode.c includes osslsigncode.c (for its static main_execute), so it
#    replaces osslsigncode.c.o and links the other objects of the sanitized build.
objs=()
for o in helpers utf msi pe cab cat appx script; do
    objs+=("build/fuzz/CMakeFiles/osslsigncode.dir/$o.c.o")
done
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
# Standalone (non-fuzzer) driver as a C object, so C linkage of LLVMFuzzerTestOneInput is kept.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o

# target:FUZZ_MODE
for t in verify:FUZZ_VERIFY extract:FUZZ_EXTRACT sign:FUZZ_SIGN script:FUZZ_SCRIPT attach:FUZZ_ATTACH; do
    name="fuzz_${t%%:*}"
    mode="${t##*:}"
    $CC -O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS \
        -std=gnu11 -fPIE -DHAVE_CONFIG_H=1 -DFUZZ_MODE="$mode" -I. -Ibuild/fuzz -Imayhem \
        -c mayhem/fuzz_osslsigncode.c -o "build/fuzz/$name.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
        "build/fuzz/$name.o" "${objs[@]}" build/fuzz/lsan_off.o -lssl -lcrypto -lz \
        -o "/mayhem/$name"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS \
        "build/fuzz/$name.o" build/fuzz/standalone_main.o "${objs[@]}" build/fuzz/lsan_off.o -lssl -lcrypto -lz \
        -o "/mayhem/$name-standalone"
done

# 3) The functional suite: upstream's own ctest suite (424 cases) against a normal Release build.
#    cmake registers the tests only when python3-cryptography is importable (installed in the Dockerfile).
cmake -S . -B build/normal -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build/normal -j"$MAYHEM_JOBS"
