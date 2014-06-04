#!/bin/sh

BUILD_COMMAND_PREPEND=autoreconf -i && ./configure $EXTRA_CONFIG
BUILD_COMMAND="make -j2"

if [ "$COVERITY_SCAN_BUILD" -eq 1 ]; then
    curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh |
        COVERITY_SCAN_PROJECT_NAME="flowgrind/flowgrind" \
        COVERITY_SCAN_NOTIFICATION_EMAIL="developer@flowgrind.net" \
        COVERITY_SCAN_BRANCH_PATTERN="coverity_scan" \
        COVERITY_SCAN_BUILD_COMMAND_PREPEND="$BUILD_COMMAND_PREPEND" \
        COVERITY_SCAN_BUILD_COMMAND="$BUILD_COMMAND" \
        bash
    exit $?
else
    $BUILD_COMMAND_PREPEND
    $BUILD_COMMAND
fi
