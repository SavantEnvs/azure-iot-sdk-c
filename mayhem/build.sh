#!/usr/bin/env bash
#
# mayhem/build.sh — build the azure-iot-sdk-c fuzz harnesses, the standalone reproducers and the test probes.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
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

# Everything the build needs (cmake, ninja, clang, uuid-dev, the git submodules) is in the image/tree;
# nothing is fetched, so this runs offline and is safe to re-run.
# The compiler reaches CMake through the CC/CXX env (not -DCMAKE_C_COMPILER=clang): a by-name -D
# disagrees with the cached absolute path on a re-run, which wipes the cache and drops the other -D options.
CMAKE_COMMON=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=Debug
  # The harnesses mock the TLS adapter themselves (tlsio_openssl_get_interface_description), so the SDK is
  # configured without OpenSSL, sockets, websockets, HTTP, blob upload, service/DPS clients and samples.
  -Duse_openssl=OFF -Duse_schannel=OFF -Duse_socketio=OFF -Duse_wsio=OFF -Duse_http=OFF
  -Ddont_use_uploadtoblob=ON -Dbuild_service_client=OFF -Dbuild_provisioning_service_client=OFF
  -Duse_prov_client=OFF -Dskip_samples=ON -Drun_unittests=OFF -Dwarnings_as_errors=OFF
)
LIB_TARGETS=(iothub_client iothub_client_mqtt_transport iothub_client_amqp_transport)

# Link line for the SDK static archives: every .a the build produced, in a group so order is irrelevant.
sdk_archives() { find "$1" -name '*.a' | sort; }
SYSLIBS=(-lm -lpthread -luuid)

# 1) SDK with the sanitizers + DWARF-3. -fsanitize=fuzzer-no-link adds coverage edges to the SDK itself
#    (even when SANITIZER_FLAGS is empty) so the fuzzer sees progress inside the protocol stacks.
# -fno-sanitize=function: upstream hands xio_setoption (XIO_HANDLE first parameter) to OptionHandler_Create as
# a `int (*)(void*, const char*, const void*)`, so UBSan's function-type check fires on every connection
# setup (optionhandler.c:246) and halts each input. Only that one UBSan check is relaxed.
NO_FN="-fno-sanitize=function"
FUZZ_CFLAGS="$SANITIZER_FLAGS $NO_FN $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake -S "$SRC" -B "$SRC/mayhem/build-fuzz" "${CMAKE_COMMON[@]}" -DCMAKE_C_FLAGS="$FUZZ_CFLAGS"
cmake --build "$SRC/mayhem/build-fuzz" -j"$MAYHEM_JOBS" --target "${LIB_TARGETS[@]}"
mapfile -t FUZZ_LIBS < <(sdk_archives "$SRC/mayhem/build-fuzz")

# Include path of the SDK build (the generated azure_macro_utils/ headers live in the build dir).
inc_for() {
  echo -I"$1" -I"$SRC/iothub_client/inc" -I"$SRC/c-utility/inc" -I"$SRC/c-utility/pal/linux" \
       -I"$SRC/c-utility/deps/c-logging/v2/inc" -I"$SRC/c-utility/deps/umock-c/inc" \
       -I"$SRC/deps/azure-macro-utils-c/inc" -I"$SRC/deps/c-logging/v2/inc" -I"$SRC/deps/umock-c/inc" \
       -I"$SRC/deps/parson" -I"$SRC/uamqp/inc" -I"$SRC/umqtt/inc" -I"$SRC/mayhem"
}

# 2) Harnesses: fuzzer + standalone reproducer + the lsan_off hook (SPEC §6.2 item 12).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/mayhem/build-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/build-fuzz/standalone_main.o"
for h in iothubclient_fuzz_amqp iothubclient_fuzz_mqtt; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $NO_FN -fsanitize=fuzzer-no-link -c $(inc_for "$SRC/mayhem/build-fuzz") "$SRC/mayhem/$h.c" -o "$SRC/mayhem/build-fuzz/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/build-fuzz/$h.o" "$SRC/mayhem/build-fuzz/lsan_off.o" \
      -Wl,--start-group "${FUZZ_LIBS[@]}" -Wl,--end-group "${SYSLIBS[@]}" -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/build-fuzz/standalone_main.o" "$SRC/mayhem/build-fuzz/$h.o" "$SRC/mayhem/build-fuzz/lsan_off.o" \
      -Wl,--start-group "${FUZZ_LIBS[@]}" -Wl,--end-group "${SYSLIBS[@]}" -lstdc++ -o "$SRC/$h-standalone"
done

# 3) Test probes with the project's normal flags (own build tree, no sanitizers, no DWARF override).
cmake -S "$SRC" -B "$SRC/mayhem/build-test" "${CMAKE_COMMON[@]}" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS"
cmake --build "$SRC/mayhem/build-test" -j"$MAYHEM_JOBS" --target "${LIB_TARGETS[@]}"
mapfile -t TEST_LIBS < <(sdk_archives "$SRC/mayhem/build-test")
for p in kat e2e_mqtt e2e_amqp; do
  $CC -O1 $COVERAGE_FLAGS $(inc_for "$SRC/mayhem/build-test") "$SRC/mayhem/kat/$p.c" \
      -Wl,--start-group "${TEST_LIBS[@]}" -Wl,--end-group "${SYSLIBS[@]}" -o "$SRC/mayhem/build-test/$p"
done
