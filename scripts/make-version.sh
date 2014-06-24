#!/bin/sh

#SCRIPTDIR=$(dirname $(readlink -f $0))
VLINE='/*#define GITVERSION ""*/'
GIT=`which git`

#cd $SCRIPTDIR/..

if [ "$GIT" = "" ]; then
    echo "The command 'git' is not installed. Please install git."
elif [ ! -d .git ]; then
    echo "This is not a git release."
else
    VERSION=$($GIT describe --always --abbrev=6)
    VLINE="#define GITVERSION \"$VERSION\""
fi

echo "$VLINE" | cmp -s - gitversion.h || echo "$VLINE" > gitversion.h
exit 0
