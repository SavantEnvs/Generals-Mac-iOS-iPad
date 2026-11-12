#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses (and the known-answer test probe) for Generals.
#
# The game itself is a Windows-era engine that cannot be built as a whole here, so each harness is
# compiled directly against the self-contained engine sources it exercises, with the same
# compatibility shims the upstream Linux CMake build uses (C++20, glibc's strlcpy family, the DXVK
# native Windows headers, the PCH contents force-included). Dependencies come from the image
# (/opt/toolchains/deps), so this script is re-runnable offline.
#
# Every engine source is compiled twice: sanitized (ASan+UBSan, SanCov) for the fuzz and -standalone
# binaries, and plain (-O2) for the known-answer probe that mayhem/test.sh runs.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS


cd "$SRC"

LZHL=/opt/toolchains/deps/lzhl-dfd96e2/src
DXVK=/opt/toolchains/deps/dxvk-2.6/src
W=$SRC/Core/Libraries/Source/WWVegas
COMP=$SRC/Core/Libraries/Source/Compression
B=$SRC/build/mayhem   # upstream's .gitignore covers /build*

INC=(-I"$W/WWDebug" -I"$W/WWMath" -I"$W/WWSaveLoad" -I"$W/WW3D2" -I"$W/WWLib" -I"$W"
     -I"$SRC/Core/Libraries/Include" -I"$SRC/Dependencies/Utility"
     -I"$SRC/GeneralsMD/Code/CompatLib/Include"
     -I"$DXVK/include/native/windows" -I"$DXVK/include/native/directx"
     -I"$COMP" -I"$LZHL" -I"$LZHL/CompLibHeader" -I"$SRC/mayhem")
PCH=(-include Utility/CppMacros.h -include always.h -include STLUtils.h -include win.h
     -include WWCommon.h -include wwstring.h -include PchCompat.h)
DEFS=(-DHAVE_STRLCPY -DHAVE_STRLCAT -DHAVE_WCSLCPY -DHAVE_WCSLCAT)
CXXBASE=(-std=c++20 -fpermissive -w -Wno-register "${DEFS[@]}" "${PCH[@]}" "${INC[@]}")

# Engine sources the harnesses link (a library that is itself the target: built here, instrumented).
ENGINE_SRCS=(
  "$COMP/CompressionManager.cpp"
  "$COMP"/EAC/*.cpp
  "$COMP/LZHCompress/NoxCompress.cpp"
  "$LZHL/CompLibHeader/Huff.cpp" "$LZHL/CompLibHeader/Lz.cpp" "$LZHL/CompLibHeader/Lzhl.cpp"
  "$W/WWLib/lzo1x_d.cpp" "$W/WWLib/lzo1x_c.cpp"
  "$W/WWLib/base64.cpp"
  "$W/WWLib/TARGA.cpp" "$W/WWLib/ramfile.cpp" "$SRC/mayhem/memfile.cpp"
)

# Sanitized flags for engine + harness objects. SanCov is injected into the library objects too
# (fuzzer-no-link), otherwise the fuzzer sees no coverage inside the code it is fuzzing.
FUZZ_CXX=($SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link "${CXXBASE[@]}")
PLAIN_CXX=(-g -O2 "${CXXBASE[@]}")

mkdir -p "$B/san" "$B/plain"

objname() { local s="$1"; echo "$(basename "${s%.*}").o"; }

compile_all() {   # compile_all <outdir> <flags-array-name> <sources...>
  local out="$1" flagsname="$2"; shift 2
  local -n flags="$flagsname"
  local pids=() s
  for s in "$@"; do
    "$CXX" "${flags[@]}" -c "$s" -o "$out/$(objname "$s")" &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  local p; for p in "${pids[@]}"; do wait "$p"; done
}

HARNESSES=(fuzz_decompress fuzz_lzo fuzz_base64 fuzz_targa)

# 1) project code, sanitized
# lzhl declares UINT32 as `unsigned long`, which is 64-bit on LP64: its compressor segfaults and its
# decoder indexes Huff.cpp's Group[16] out of range on any real stream, so no valid LZHL data could
# get past UBSan. Build it with the 32-bit UINT32 the code was written for (both the fuzz and the
# test builds); everything else is built exactly as upstream does.
LZHL_SRCS=("$LZHL/CompLibHeader/Huff.cpp" "$LZHL/CompLibHeader/Lz.cpp" "$LZHL/CompLibHeader/Lzhl.cpp")
FUZZ_LZHL_CXX=($SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -std=c++20 -fpermissive -w "-DUINT32=unsigned int" -I"$LZHL" -I"$LZHL/CompLibHeader")
OTHER_SRCS=()
for s in "${ENGINE_SRCS[@]}"; do
  case "$s" in "$LZHL"/*) ;; *) OTHER_SRCS+=("$s") ;; esac
done
compile_all "$B/san" FUZZ_CXX "${OTHER_SRCS[@]}"
compile_all "$B/san" FUZZ_LZHL_CXX "${LZHL_SRCS[@]}"
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/san/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$B/san/standalone_main.o"

# 2) each harness twice: libFuzzer engine, and the standalone run-once reproducer
for h in "${HARNESSES[@]}"; do
  "$CXX" "${FUZZ_CXX[@]}" -c "$SRC/mayhem/$h.cpp" -o "$B/san/$h.o"
done

# link: engine objects (not other harnesses) + the harness
ENGINE_OBJS=()
for s in "${ENGINE_SRCS[@]}"; do ENGINE_OBJS+=("$B/san/$(objname "$s")"); done
ENGINE_OBJS+=("$B/san/lsan_off.o")
for h in "${HARNESSES[@]}"; do
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/san/$h.o" "${ENGINE_OBJS[@]}" -lz -o "/mayhem/$h"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/san/$h.o" "$B/san/standalone_main.o" "${ENGINE_OBJS[@]}" -lz -o "/mayhem/$h-standalone"
done

# 3) the known-answer probe, normal flags, no sanitizers
PLAIN_LZHL_CXX=(-std=c++20 -fpermissive -w -g -O2 "-DUINT32=unsigned int" -I"$LZHL" -I"$LZHL/CompLibHeader")
compile_all "$B/plain" PLAIN_CXX "${OTHER_SRCS[@]}"
compile_all "$B/plain" PLAIN_LZHL_CXX "${LZHL_SRCS[@]}"
"$CXX" "${PLAIN_CXX[@]}" -c "$SRC/mayhem/kat.cpp" -o "$B/plain/kat.o"
PLAIN_OBJS=()
for s in "${ENGINE_SRCS[@]}"; do PLAIN_OBJS+=("$B/plain/$(objname "$s")"); done
"$CXX" "$B/plain/kat.o" "${PLAIN_OBJS[@]}" -lz -o /mayhem/kat
