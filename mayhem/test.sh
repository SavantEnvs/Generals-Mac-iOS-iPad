#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests for the engine's data decoders (already built by mayhem/build.sh).
#
# /mayhem/kat is linked with the project's normal flags (no sanitizers) against the same engine
# sources the fuzzers use. Each check below runs it and compares what it prints with a constant that
# was computed independently of the engine (FNV-1a over the plaintext, computed in Python; Targa pixel
# values worked out by hand from the file format), so a patch that makes the decoders return nothing,
# the wrong bytes, or exit early fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


KAT=/mayhem/kat
[ -x "$KAT" ] || { echo "missing $KAT: mayhem/build.sh did not build the probe" >&2; emit_ctrf "kat" 0 1 0; exit 1; }

PASSED=0; FAILED=0
check() {   # check <name> <expected> <actual>
  if [ "$2" == "$3" ]; then PASSED=$((PASSED+1)); echo "PASS $1"
  else FAILED=$((FAILED+1)); echo "FAIL $1"; echo "  expected: $2"; echo "  actual:   $3"; fi
}

PLAIN_FNV=e825d349      # plaintext(4096) of mayhem/kat.cpp
TEXT_FNV=ceb19eea       # plaintext(1500)
SMALL_FNV=f64ec2ca      # plaintext(200)

# Every codec round-trips the 4096-byte buffer.
want=$(cat <<EOF2
plain fnv=$PLAIN_FNV
RefPack: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
LZHL: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 1 (fast): compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 2: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 3: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 4: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 5 (default): compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 6: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 7: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 8: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
ZLib 9 (slow): compressed=1 decompressed=4096 fnv=$PLAIN_FNV
BTree: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
Huff: compressed=1 decompressed=4096 fnv=$PLAIN_FNV
EOF2
)
check "compression round trip, all codecs" "$want" "$("$KAT" roundtrip 2>&1)"

# Stored blobs (made with the engine's own encoders) decode to the known plaintext. The type id is
# CompressionType: 1 refpack, 2 nox/lzhl, 3 zlib1, 7 zlib5, 11 zlib9, 12 btree. (Huff decode is covered by the round trip: HUFF_decompress reads one byte past the source end on valid streams, so no Huff seed can run under ASan.)
SEEDS=/mayhem/mayhem/fuzz_decompress/testsuite
for entry in refpack:1 nox:2 zlib1:3 zlib5:7 zlib9:11 btree:12; do
  name=${entry%%:*}; type=${entry##*:}
  check "decompress ${name}_text" "type=$type usize=1500 actual=1500 fnv=$TEXT_FNV" "$("$KAT" decompress "$SEEDS/${name}_text.bin" 2>&1)"
  check "decompress ${name}_small" "type=$type usize=200 actual=200 fnv=$SMALL_FNV" "$("$KAT" decompress "$SEEDS/${name}_small.bin" 2>&1)"
done

# A truncated zlib stream must be refused (0 bytes), not decoded.
TMP=${TMPDIR:-/tmp}/kat.$$
mkdir -p "$TMP"
head -c 40 "$SEEDS/zlib5_text.bin" > "$TMP/truncated.bin"
check "truncated zlib stream is refused" "type=7 usize=1500 actual=0 fnv=$(printf '%08x' 2166136261)" "$("$KAT" decompress "$TMP/truncated.bin" 2>&1)"
rm -rf "$TMP"

# Base64: the decoder must invert the encoder and report the byte counts.
out=$("$KAT" base64 2>&1)
check "base64 round trip" "dec=Hello, Generals! n=16" "$(echo "$out" | sed -n 's/^enc=[^ ]* n=24 \(dec=.*\)$/\1/p')"

# LZO1X: compress, then decompress back to the original bytes.
check "lzo round trip" "compress=0 decompress=0 len=4096 fnv=$PLAIN_FNV smaller=1" "$("$KAT" lzo 2>&1)"

# Targa: a 2x2 24-bit image, stored raw, stored with the bottom-up flag, and RLE-compressed.
want=$(cat <<EOF2
raw: err=0 w=2 h=2 depth=24 px=1,2,3,4,5,6,7,8,9,10,11,12
raw-yflip: err=0 w=2 h=2 depth=24 px=7,8,9,10,11,12,1,2,3,4,5,6
rle: err=0 w=2 h=2 depth=24 px=20,21,22,20,21,22,30,31,32,40,41,42
badtype: err=-6 w=2 h=2 depth=24 px=
EOF2
)
check "targa raw / flipped / rle / unsupported type" "$want" "$("$KAT" targa 2>&1)"

emit_ctrf "kat" "$PASSED" "$FAILED" 0
