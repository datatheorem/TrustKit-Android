#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

# Signs the bundle when SIGNING_KEY and SIGNING_KEY_PASSWORD are set.
VERSION="$(trustkit_version)"
REPOSITORY="trustkit/build/release-bundle"
BUNDLE="${PWD}/output/trustkit-${VERSION}.zip"
rm -rf "$REPOSITORY" "$BUNDLE"
mkdir -p output

./gradlew :trustkit:publishReleasePublicationToReleaseBundleRepository

# Only the version folder: Central does not want the artifact-level maven-metadata.xml.
(cd "$REPOSITORY" && zip -qr "$BUNDLE" "com/datatheorem/android/trustkit/trustkit/${VERSION}")
unzip -l "$BUNDLE"
