#!/bin/sh
VERSION=$1

SCRIPTDIR=$(dirname $(readlink -f $0))
cd $SCRIPTDIR/..

if [ "$VERSION" = "" ]; then
	echo "Usage: $0 VERSION\n    Where VERSION is the version number of an git tag."
	exit 1
fi

GIT=`which git`
if [ "$GIT" = "" ]; then
	echo "The 'git' is not installed."
	exit 1
fi

AUTORECONF=`which autoreconf`
if [ "$AUTORECONF" = "" ]; then
	echo "Please install autotools (apt-get install autoconf automake libtool)."
	exit 1
fi

$GIT clone git://github.com/flowgrind/flowgrind.git flowgrind-$VERSION
if [ $? -ne 0 ]; then
	echo "cloning master 'flowgrind' failed."
	exit 1
fi

cd flowgrind-$VERSION

$GIT checkout tags/flowgrind-$VERSION

if [ $? -ne 0 ]; then
	echo "switching to tag 'flowgrind-$VERSION' failed."
	exit 1
fi

$AUTORECONF -i
if [ $? -ne 0 ]; then
	echo "'autoreconf -i' failed. See error messages above."
	exit 1
fi

$GIT checkout -- INSTALL
find . -type d -name ".git" | xargs rm -r

./scripts/reformat-code.sh

rm -r autom4te.cache ChangeLog RELEASEWORKFLOW .gitignore ./scripts

cd ..

tar -cjf flowgrind-$VERSION.tar.bz2 flowgrind-$VERSION
if [ $? -ne 0 ]; then
	echo "failed to create the tarball."
	exit 1
fi

gpg --armor --sign --detach-sig flowgrind-$VERSION.tar.bz2

rm -r flowgrind-$VERSION

echo "Success: Built tarball flowgrind-$VERSION.tar.bz2"

