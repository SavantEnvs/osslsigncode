#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
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

OSSL="$SRC/build/normal/osslsigncode"
TESTING="$SRC/build/normal/Testing"
CERTS="$TESTING/certs"
FILES="$TESTING/files"
[ -x "$OSSL" ] || { echo "build/normal/osslsigncode missing: mayhem/build.sh must build it" >&2; emit_ctrf "osslsigncode" 0 1 0; exit 1; }

# 1) upstream's own ctest suite (sign/verify/extract/attach/timestamp round trips for every format).
ctest_out="$(ctest --test-dir "$SRC/build/normal" --output-on-failure 2>&1)"
echo "$ctest_out" | tail -15
passed=0; failed=0
if line="$(echo "$ctest_out" | grep -E 'tests passed, [0-9]+ tests failed out of [0-9]+' | tail -1)"; then
  total="${line##* }"; failed="$(echo "$line" | sed -E 's/.*, ([0-9]+) tests failed.*/\1/')"
  passed=$(( total - failed ))
else
  failed=1
fi

# 2) known-answer probes, independent of ctest: fixed input file -> exact expected output.
#    (the suite's first tests generate $CERTS/cert.p12 and friends, so this runs after it)
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
check() {   # check <name> <ok-condition-exit-status>
  if [ "$2" -eq 0 ]; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "KAT FAIL: $1" >&2; fi
}
has() { grep -qF -- "$2" "$1"; }   # has <file> <literal>
VERIFY=(-CAfile "$CERTS/CACert.pem" -CRLfile "$CERTS/CACertCRL.pem")
SIGN=(sign -pkcs12 "$CERTS/cert.p12" -readpass "$CERTS/password.txt" -h sha256)

# unsigned PE: no signature, and the PE checksum of the fixture
"$OSSL" verify -in "$FILES/unsigned.exe" > "$W/v.txt" 2>&1; rc=$?
[ "$rc" -ne 0 ] && has "$W/v.txt" "No signature found" && has "$W/v.txt" "PE checksum   : 0002019C"
check "verify unsigned.exe reports no signature + checksum 0002019C" $?

# sign -> verify -> exact Authenticode SHA256 digest of each fixture
kat_digest() {   # kat_digest <ext> <expected current-message-digest>
  local e="$1" want="$2"
  "$OSSL" "${SIGN[@]}" -in "$FILES/unsigned.$e" -out "$W/s.$e" > "$W/sign.$e.txt" 2>&1
  "$OSSL" verify "${VERIFY[@]}" -in "$W/s.$e" > "$W/ver.$e.txt" 2>&1; local rc=$?
  [ "$rc" -eq 0 ] && has "$W/ver.$e.txt" "Signature verification: ok" \
    && has "$W/ver.$e.txt" "Current message digest    : $want "
  check "sign+verify unsigned.$e digest $want" $?
}
kat_digest exe  2D2C7B382C8163A419B9FF214A7B651C33F9EA43335907F11377290C5158A7A4
kat_digest ex_  44C475C1872C7CDDA6D60D8D2A9A8872454BE3B3263A2ECEDABB164D7E65DAD6
kat_digest ps1  1DC1589366037D7375BC75FA387D1FFEED1BA9935A1DB5CAA1B788CEEC0FCF55
kat_digest psc1 11FDE0EE7FA119389339E02C4D0F6C9D17B80CBC1986CA00DBA09EF61C0C1E85
kat_digest js   768FD6CC112BA93B79C8678A3A8D2E6D980D6BC7BDB3E5FFA92DC4941F82D91E
kat_digest mof  21119DB924DD40DDA6E42CD531A3BCAB7CED776EBBCC736934FD71A121AE3CE2
kat_digest 256appx DC5C643D237E093A2732BD23B85889EF04DDDA5B2D1AE5A1C48460DE6324073C
for e in cat msi; do   # no single "current message digest" line in these formats
  "$OSSL" "${SIGN[@]}" -in "$FILES/unsigned.$e" -out "$W/s.$e" > /dev/null 2>&1
  "$OSSL" verify "${VERIFY[@]}" -in "$W/s.$e" > "$W/ver.$e.txt" 2>&1; rc=$?
  [ "$rc" -eq 0 ] && has "$W/ver.$e.txt" "Signature verification: ok" && has "$W/ver.$e.txt" "Number of verified signatures: 1"
  check "sign+verify unsigned.$e" $?
done

# a signed file that is modified afterwards must fail verification
cp "$W/s.exe" "$W/t.exe"
printf '\x41' | dd of="$W/t.exe" bs=1 seek=4096 conv=notrunc status=none
"$OSSL" verify "${VERIFY[@]}" -in "$W/t.exe" > "$W/v.txt" 2>&1; rc=$?
[ "$rc" -ne 0 ] && has "$W/v.txt" "Signature verification: failed"
check "verify rejects a tampered signed.exe" $?

# remove-signature -> unsigned again, and the original checksum comes back to a stable value
"$OSSL" remove-signature -in "$W/s.exe" -out "$W/r.exe" > /dev/null 2>&1
"$OSSL" verify -in "$W/r.exe" > "$W/v.txt" 2>&1; rc=$?
[ "$rc" -ne 0 ] && has "$W/v.txt" "No signature found"
check "remove-signature leaves no signature" $?

# extract-signature then attach-signature reproduces a verifiable, same-digest file
"$OSSL" extract-signature -in "$W/s.ps1" -out "$W/sig.p7" > /dev/null 2>&1
"$OSSL" attach-signature -sigin "$W/sig.p7" -in "$FILES/unsigned.ps1" -out "$W/a.ps1" > /dev/null 2>&1
"$OSSL" verify "${VERIFY[@]}" -in "$W/a.ps1" > "$W/v.txt" 2>&1; rc=$?
[ "$rc" -eq 0 ] && has "$W/v.txt" "Signature verification: ok" \
  && has "$W/v.txt" "Current message digest    : 1DC1589366037D7375BC75FA387D1FFEED1BA9935A1DB5CAA1B788CEEC0FCF55 "
check "extract-signature + attach-signature round trip (ps1)" $?

emit_ctrf "ctest+kat" "$passed" "$failed" 0
