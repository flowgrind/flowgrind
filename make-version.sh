#!/bin/sh

NOGIT='/*#define GITVERSION ""*/'
GIT=`which git`
if [ "$GIT" = "" ]; then
	echo "The 'git' command is not installed."
	if ! echo $NOGIT | md5sum - | sed 's|-|gitversion.h|' | md5sum -c
	then
		echo "$NOGIT" >gitversion.h
	fi
	exit 0 
fi

if [ ! -d .git ]; then
	echo "This is not a git release."
	if ! echo $NOGIT | md5sum - | sed 's|-|gitversion.h|' | md5sum -c
	then
		echo "$NOGIT" >gitversion.h
	fi
	exit 0
fi

VERSION=$($GIT describe --always --abbrev=6)

VGIT="#define GITVERSION \"$VERSION\""
if ! echo $VGIT | md5sum - | sed 's|-|gitversion.h|' | md5sum -c
then
	echo "$VGIT" >gitversion.h
fi
