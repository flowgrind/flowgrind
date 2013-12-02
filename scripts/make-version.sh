#!/bin/sh

GIT=`which git`
if [ "$GIT" = "" ]; then
	echo "The 'git' command is not installed."
	echo "/*#define GITVERSION \"\"*/" >../gitversion.h
	exit 0
fi

if [ ! -d .git ]; then
	echo "This is not a git release."
	echo "/*#define GITVERSION \"\"*/" >../gitversion.h
	exit 0
fi

VERSION=$($GIT describe --always --abbrev=6)

echo "#define GITVERSION \"$VERSION\"" >../gitversion.h

