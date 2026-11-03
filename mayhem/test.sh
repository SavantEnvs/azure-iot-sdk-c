#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the azure-iot-sdk-c behavioural probes (already built by mayhem/build.sh).
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

# Probes (mayhem/kat/*.c, built by build.sh with the project's normal flags). Each prints one
# "PASS <name>" / "FAIL <name>" line per assertion and a "<probe> failures: N" summary line:
#   kat       known-answer tests: base64, HMAC-SHA256 (RFC 4231), URL encoding, SAS token signature,
#             IoT Hub message API
#   e2e_mqtt  real device client over the MQTT transport against the in-process mock broker
#   e2e_amqp  real device client over the AMQP transport against the canned hub conversation
# Expected number of assertions per probe: a probe that exits early (or is replaced by a no-op) cannot
# reach it, so that counts as failure.
declare -A EXPECT=( [kat]=22 [e2e_mqtt]=15 [e2e_amqp]=9 )
passed=0; failed=0
for p in kat e2e_mqtt e2e_amqp; do
  bin="$SRC/mayhem/build-test/$p"
  if [ ! -x "$bin" ]; then echo "missing $bin — mayhem/build.sh did not build it" >&2; failed=$((failed+1)); continue; fi
  out="$(timeout 300 "$bin" 2>&1)"; rc=$?
  p_n=$(printf '%s\n' "$out" | grep -c '^PASS ')
  f_n=$(printf '%s\n' "$out" | grep -c '^FAIL ')
  printf '%s\n' "$out" | grep -E '^(FAIL |  got:|  want:)' || true
  echo "$p: pass=$p_n fail=$f_n rc=$rc"
  passed=$((passed+p_n)); failed=$((failed+f_n))
  if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -q "^$p failures: 0\$" || [ "$((p_n+f_n))" -ne "${EXPECT[$p]}" ]; then
    [ "$f_n" -gt 0 ] || failed=$((failed+1))
  fi
done

emit_ctrf "azure-iot-sdk-c-probes" "$passed" "$failed" 0
