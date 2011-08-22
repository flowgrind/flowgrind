#!/bin/sh
VERSION=$1

if [ "$VERSION" = "" ]; then
	echo "Usage: $0 VERSION\n    Where VERSION is the version number of an svn tag."
	exit 1
fi

SVN=`which svn`
if [ "$SVN" = "" ]; then
	echo "The subversion command 'svn' is not installed."
	exit 1
fi

AUTORECONF=`which autoreconf`
if [ "$AUTORECONF" = "" ]; then
	echo "Please install autotools (apt-get install autoconf automake libtool)."
	exit 1
fi

$SVN co svn+ssh://svn.umic-mesh.net/umic-mesh/projects/flowgrind/tags/flowgrind-$VERSION
if [ $? -ne 0 ]; then
	echo "Exporting subversion tag 'flowgrind-$VERSION' failed."
	exit 1
fi

cd flowgrind-$VERSION
$AUTORECONF -i
if [ $? -ne 0 ]; then
	echo "'autoreconf -i' failed. See error messages above."
	exit 1
fi

$SVN revert INSTALL
find . -type d -name ".svn" | xargs rm -r
rm -r config.h.in~ autom4te.cache ChangeLog dist.sh RELEASEWORKFLOW 
./reformat-code.sh

cd ..

tar -cjf flowgrind-$VERSION.tar.bz2 flowgrind-$VERSION
if [ $? -ne 0 ]; then
	echo "failed to create the tarball."
	exit 1
fi

rm -r flowgrind-$VERSION

echo "Success: Built tarball flowgrind-$VERSION.tar.bz2"
