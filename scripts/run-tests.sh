#!/bin/sh

if [ -n "$COVERITY_SCAN_BUILD" ]; then
    curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh |
        COVERITY_SCAN_PROJECT_NAME="flowgrind/flowgrind" \
        COVERITY_SCAN_NOTIFICATION_EMAIL="developer@flowgrind.net" \
        COVERITY_SCAN_BRANCH_PATTERN="coverity_scan" \
        COVERITY_SCAN_BUILD_COMMAND_PREPEND="autoreconf -i && ./configure $EXTRA_CONFIG" \
        COVERITY_SCAN_BUILD_COMMAND="make -j2" \
        bash
    exit $?
else
    autoreconf -i
    ./configure $EXTRA_CONFIG
    make -j2
fi
