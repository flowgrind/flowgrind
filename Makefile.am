SUBDIRS = src doc
CLEANFILES = gitversion.h
BUILT_SOURCES = gitversion.h

dist_man1_MANS = man/flowgrind.1 \
				 man/flowgrindd.1 \
				 man/flowgrind-stop.1

.PHONY: gitversion.h

gitversion.h:
	$(shellL) ./scripts/make-version.sh

