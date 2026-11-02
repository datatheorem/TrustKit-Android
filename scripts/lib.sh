#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

cd "$(dirname "$0")/.."

# stderr, so a failure inside $(...) is still shown.
fail() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::error::$*" >&2
    else
        echo "error: $*" >&2
    fi
    exit 1
}

trustkit_version() {
    local version
    version="$(sed -n 's/^trustkitVersionName = "\(.*\)"$/\1/p' gradle/libs.versions.toml)"
    [[ -n "$version" ]] || fail "Could not read trustkitVersionName from gradle/libs.versions.toml."
    echo "$version"
}
