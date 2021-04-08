#!/bin/sh
#
# Based on https://merowing.info/2021/01/improve-build-times-by-extracting-3rd-party-tooling-to-processing-script./

cd "$(dirname "$0")/.."

if [[ -n "$CI" ]] || [[ "$1" == "--fail-on-errors" ]]; then
  fail_on_errors=true
  echo "Running in --fail-on-errors mode"
else
  echo "Running in local mode"
fi

final_status=0

function process_output() {
  printf '\n# Running %s\n' "$1"
  local start=$(date +%s)
  local output=$(eval "$2" 2>&1)
  if [[ ! -z "$output" ]]; then
    printf -- '---\n%s\n---\n' "$output"
    if [ "$fail_on_errors" = true ]; then
      final_status=1
    fi
  fi
  local end=$(date +%s)
  printf 'Execution time was %s seconds.\n' "$(($end - $start))"
}

process_output "SwiftFormat" "python ./Scripts/git-format-staged.py -f 'swiftformat stdin --stdinpath \"{}\" --quiet' '*.swift'"
process_output "SwiftLint" "python ./Scripts/git-format-staged.py --no-write -f 'swiftlint --use-stdin --quiet >&2' '*.swift'"

if [[ "$final_status" -gt 0 ]]; then
  echo "\nChanges werde made or are required. Please review the output above for further details."
fi

exit $final_status
