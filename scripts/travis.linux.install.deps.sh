#!/bin/sh

# parse packages in $PACKAGES
EXTRA_PKGS=
for PACKAGE in $PACKAGES; do
    case $PACKAGE in
        gsl)
            EXTRA_PKGS="libgsl0-dev $EXTRA_PKGS"
            ;;
        libpcap)
            EXTRA_PKGS="libpcap-dev $EXTRA_PKGS"
            ;;
    esac
done

set -x
sudo apt-get -qq install libxmlrpc-c3-dev libcurl4-gnutls-dev $EXTRA_PKGS

