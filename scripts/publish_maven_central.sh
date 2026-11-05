#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

: "${MAVEN_CENTRAL_USERNAME:?Set MAVEN_CENTRAL_USERNAME to the Central Portal user token username}"
: "${MAVEN_CENTRAL_PASSWORD:?Set MAVEN_CENTRAL_PASSWORD to the Central Portal user token password}"

VERSION="$(trustkit_version)"
BUNDLE="output/trustkit-${VERSION}.zip"
API="https://central.sonatype.com/api/v1/publisher"
DEPLOYMENTS="https://central.sonatype.com/publishing/deployments"

[[ -f "$BUNDLE" ]] || fail "$BUNDLE not found. Run scripts/build_release_bundle.sh first."
unzip -l "$BUNDLE" "*/trustkit-${VERSION}.aar.asc" >/dev/null 2>&1 ||
    fail "$BUNDLE is not signed. Set SIGNING_KEY and SIGNING_KEY_PASSWORD, then run scripts/build_release_bundle.sh again."

TOKEN="$(printf '%s:%s' "$MAVEN_CENTRAL_USERNAME" "$MAVEN_CENTRAL_PASSWORD" | base64 | tr -d '\n')"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::add-mask::$TOKEN"
fi

# The header goes in on stdin: a -H argument would show the token in the process list.
central_api() {
    printf 'Authorization: Bearer %s\n' "$TOKEN" | curl --fail-with-body -sS -X POST -H @- "$@"
}

# No --retry here: a repeated upload creates a second deployment.
if ! DEPLOYMENT_ID="$(central_api --form "bundle=@${BUNDLE}" \
    "$API/upload?publishingType=AUTOMATIC&name=trustkit-${VERSION}")"; then
    fail "Central Portal rejected the upload: $DEPLOYMENT_ID"
fi
echo "Uploaded $BUNDLE as Central Portal deployment $DEPLOYMENT_ID: $DEPLOYMENTS"

STATE=""
for _ in $(seq 120); do
    if ! RESPONSE="$(central_api --retry 3 "$API/status?id=${DEPLOYMENT_ID}")"; then
        fail "Could not read the status of deployment $DEPLOYMENT_ID: $RESPONSE. The upload already happened, so do not re-run this job. Check $DEPLOYMENTS."
    fi
    STATE="$(jq -r .deploymentState <<<"$RESPONSE")"
    echo "Deployment state: $STATE"
    case "$STATE" in
        PUBLISHED) exit 0 ;;
        FAILED)
            jq . <<<"$RESPONSE"
            fail "Central Portal rejected deployment $DEPLOYMENT_ID. See the errors above or $DEPLOYMENTS."
            ;;
    esac
    sleep 20
done
fail "Deployment $DEPLOYMENT_ID is still $STATE after 40 minutes. The upload already happened, so do not re-run this job. Check $DEPLOYMENTS."
