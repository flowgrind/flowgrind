SUBDIRS = src
EXTRA_DIST = build-aux/config.rpath configure make-version.pl RELEASEWORKFLOW ./scripts/reformat-code.sh
CLEANFILES = gitversion.h
BUILT_SOURCES = gitversion.h

FORCE:

gitversion.h: FORCE
	$(shellL) ./scripts/make-version.sh

dist_man1_MANS = man/flowgrind.1 \
		 man/flowgrindd.1 \
		 man/flowgrind-stop.1

