#!/bin/sh

VERSION=$1

cd $(dirname $0)/..

if [ "$VERSION" = "" ]; then
    echo -e "Usage: $0 VERSION\n    Where VERSION is the version number of an git tag."
    exit 1
fi

GIT=`which git`
if [ "$GIT" = "" ]; then
    echo "The command 'git' is not installed. Please install git (apt-get install git)"
    exit 1
fi

AUTORECONF=`which autoreconf`
if [ "$AUTORECONF" = "" ]; then
    echo "Please install autotools (apt-get install autoconf automake libtool)."
    exit 1
fi

$GIT clone git://github.com/flowgrind/flowgrind.git flowgrind-$VERSION
if [ $? -ne 0 ]; then
    echo "Cloning master 'flowgrind' failed."
    exit 1
fi

cd flowgrind-$VERSION

$GIT checkout tags/flowgrind-$VERSION
if [ $? -ne 0 ]; then
    echo "Switching to tag 'flowgrind-$VERSION' failed."
    exit 1
fi

$AUTORECONF -i
if [ $? -ne 0 ]; then
    echo "'autoreconf -i' failed. See error messages above."
    exit 1
fi

$GIT checkout -- INSTALL
find . -type d -name ".git" | xargs rm -r

rm -r autom4te.cache .valgrind.supp .gitignore .travis.yml

cd ..

tar -cjf flowgrind-$VERSION.tar.bz2 flowgrind-$VERSION
if [ $? -ne 0 ]; then
    echo "Failed to create the tarball."
    exit 1
fi

gpg --armor --sign --detach-sig flowgrind-$VERSION.tar.bz2

rm -r flowgrind-$VERSION

echo "Success: Built tarball flowgrind-$VERSION.tar.bz2"
exit 0
