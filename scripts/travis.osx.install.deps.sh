#!/bin/sh

# parse packages in $PACKAGES
EXTRA_PKGS=
for PACKAGE in $PACKAGES; do
    case $PACKAGE in
        gsl)
            EXTRA_PKGS="gsl $EXTRA_PKGS"
            ;;
        libpcap)
            # Apple distributes libpcap with OS X, no action needed
            ;;
    esac
done

set -x
brew install xmlrpc-c gettext $EXTRA_PKGS

