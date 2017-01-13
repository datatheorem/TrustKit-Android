#!/bin/bash
if [ "$TRAVIS_BRANCH" == "master" ]; then
    echo $TRAVIS_BRANCH;
    ./gradlew install bintrayUpload;
fi