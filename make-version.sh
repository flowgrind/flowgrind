#!/bin/sh

NOGIT='/*#define GITVERSION ""*/'
GIT=`which git`
if [ "$GIT" = "" ]; then
	echo "The 'git' command is not installed."
	if ! echo $NOGIT | md5sum - | sed 's|-|gitversion.h|' | md5sum -c
	then
		echo "/*#define GITVERSION \"\"*/" >gitversion.h
	fi
	exit 0 
fi

if [ ! -d .git ]; then
	echo "This is not a git release."
	if ! echo $NOGIT | md5sum - | sed 's|-|gitversion.h|' | md5sum -c
	then
		echo "/*#define GITVERSION \"\"*/" >gitversion.h
	fi
	exit 0
fi

VERSION=$($GIT describe --always --abbrev=6)

echo "#define GITVERSION \"$VERSION\"" >gitversion.h


