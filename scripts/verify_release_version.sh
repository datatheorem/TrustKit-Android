#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

TAG="${1:?usage: $0 <release tag>}"
VERSION="$(trustkit_version)"

[[ "${TAG#v}" == "$VERSION" ]] ||
    fail "Release tag '$TAG' does not match trustkitVersionName '$VERSION'. Tag the commit that sets this version."
[[ "$VERSION" != *-SNAPSHOT ]] ||
    fail "Snapshot version '$VERSION' cannot be released to Maven Central."

POM_URL="https://repo1.maven.org/maven2/com/datatheorem/android/trustkit/trustkit/${VERSION}/trustkit-${VERSION}.pom"
STATUS="$(curl -sS --retry 3 -o /dev/null -w '%{http_code}' "$POM_URL" || true)"
case "$STATUS" in
    404) echo "TrustKit $VERSION is not on Maven Central yet. OK to release." ;;
    200) fail "Version $VERSION is already on Maven Central. Bump trustkitVersionName and create a new release." ;;
    *) fail "Could not check Maven Central for $VERSION (HTTP $STATUS). Re-run the workflow." ;;
esac
