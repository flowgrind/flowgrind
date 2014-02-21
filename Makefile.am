SUBDIRS = src
EXTRA_DIST = build-aux/config.rpath configure ./scripts/make-version.sh ./scripts/make-release.sh
CLEANFILES = gitversion.h
BUILT_SOURCES = gitversion.h

FORCE:

gitversion.h: FORCE
	$(shellL) ./scripts/make-version.sh

dist_man1_MANS = man/flowgrind.1 \
		 man/flowgrindd.1 \
		 man/flowgrind-stop.1

