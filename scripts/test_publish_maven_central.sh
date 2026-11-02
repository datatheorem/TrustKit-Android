#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

# Runs publish_maven_central.sh in a throwaway copy of the repo, against a fake curl.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/gradle" "$WORK/bin" "$WORK/output"
cp -R scripts "$WORK/"
echo 'trustkitVersionName = "9.9.9"' >"$WORK/gradle/libs.versions.toml"

cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$CALLS"
case "${*: -1}" in
    *publisher/upload*)
        if [[ "$SCENARIO" == upload-rejected ]]; then echo '{"error":"Invalid token"}'; exit 22; fi
        echo -n "deployment-1" ;;
    *publisher/status*)
        case "$SCENARIO" in
            rejected) echo '{"deploymentState":"FAILED","errors":["Missing javadoc"]}' ;;
            stuck) echo '{"deploymentState":"PUBLISHING"}' ;;
            *) if (($(grep -c publisher/status "$CALLS") < 2)); then echo '{"deploymentState":"VALIDATING"}'; else echo '{"deploymentState":"PUBLISHED"}'; fi ;;
        esac ;;
esac
EOF
printf '#!/usr/bin/env bash\n' >"$WORK/bin/sleep"
chmod +x "$WORK/bin/"*

# Same files as a real bundle. A short listing hides bugs that only show with the real size.
make_bundle() {
    local signed="$1" dir="$WORK/repo/com/datatheorem/android/trustkit/trustkit/9.9.9" suffix sum f
    local files=()
    rm -rf "$WORK/repo" "$WORK/output/trustkit-9.9.9.zip"
    mkdir -p "$dir"
    for suffix in .aar .pom .module -sources.jar -javadoc.jar; do
        files+=("$dir/trustkit-9.9.9$suffix")
        if $signed; then files+=("$dir/trustkit-9.9.9$suffix.asc"); fi
    done
    for f in "${files[@]}"; do
        touch "$f"
        for sum in md5 sha1 sha256 sha512; do touch "$f.$sum"; done
    done
    (cd "$WORK/repo" && zip -qr "$WORK/output/trustkit-9.9.9.zip" .)
}

FAILED=0
expect() {
    local scenario="$1" want_exit="$2" want_text="$3" out rc
    : >"$WORK/calls"
    # GITHUB_ACTIONS is unset so the expected failures do not show up as CI annotations.
    out="$(env -u GITHUB_ACTIONS PATH="$WORK/bin:$PATH" CALLS="$WORK/calls" SCENARIO="$scenario" \
        MAVEN_CENTRAL_USERNAME=user MAVEN_CENTRAL_PASSWORD=pass \
        "$WORK/scripts/publish_maven_central.sh" 2>&1)" && rc=0 || rc=$?
    if [[ $rc -eq $want_exit && "$out" == *"$want_text"* ]]; then
        echo "ok: $scenario"
    else
        echo "FAIL: $scenario exited $rc, expected $want_exit and output containing '$want_text':"
        echo "$out"
        FAILED=1
    fi
}

make_bundle true
expect published 0 "Deployment state: PUBLISHED"
expect rejected 1 "Missing javadoc"
expect upload-rejected 1 "Invalid token"
expect stuck 1 "do not re-run this job"

make_bundle false
expect unsigned 1 "is not signed"
if [[ -s "$WORK/calls" ]]; then
    echo "FAIL: unsigned: the bundle was uploaded"
    FAILED=1
fi

exit $FAILED
