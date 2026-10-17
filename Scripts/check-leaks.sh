#!/usr/bin/env bash
#
# Runs the test suite on macOS under `leaks` and fails when the test process leaks memory,
# such as a CommonCrypto cryptor that never reaches `CCCryptorRelease`.
#
# The exit status of `leaks` ignores test results, so the Swift Testing summary is checked too.
# `leaks` scans conservatively, so a stale pointer can hide a leak. `MallocScribble` makes those rarer.
# After Xcode, macOS or CI runner changes, confirm the check still works by temporarily removing
# the `CCCryptorRelease` call from `AesSiv.Cmac.deinit` and expecting this script to fail.
set -euo pipefail

cd "$(dirname "$0")/.."

# xctest runs no Swift Testing tests from a bundle built by the native build system,
# which is the default before Swift 6.4, so swiftbuild is pinned.
swift build --build-system swiftbuild --build-tests
bin_path="$(swift build --build-system swiftbuild --build-tests --show-bin-path)"
xctest_path="$(xcrun --find xctest)"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# `leaks` launches Xcode's xctest binary directly. `swiftpm-testing-helper` cannot load
# XCTest.framework under SIP, and an `env` wrapper hides the test process from `leaks`.
status=0
MallocScribble=1 leaks --atExit -- "$xctest_path" "$bin_path/CryptomatorCryptoLibTests.xctest" 2>&1 | tee "$log" || status=$?

if [[ $status -ne 0 ]]; then
  echo "leaks exited with status $status (1: leaks found, above 1: leaks failed)" >&2
  exit 1
elif ! grep -Eq 'Process [0-9]+: [0-9]+ leaks? for' "$log"; then
  echo "leaks printed no leak report" >&2
  exit 1
# Test output can contain summary-like text, and buffered stdout can land after the real summary
# or on its line. So exactly one summary may appear anywhere, and it must pass.
elif [[ $(grep -Eo 'Test run with [0-9]+ tests? in [0-9]+ suites? (passed|failed) after' "$log" | wc -l) -ne 1 ]] \
  || ! grep -Eq '^[^[:space:]]+ Test run with [1-9][0-9]* tests? in [0-9]+ suites? passed after' "$log"; then
  echo "Swift Testing did not report a passing run" >&2
  exit 1
fi
