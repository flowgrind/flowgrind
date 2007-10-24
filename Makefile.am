SUBDIRS = src
EXTRA_DIST = configure make-version.pl version.conf
CLEANFILES = svnversion.h
BUILT_SOURCES = svnversion.h

FORCE:

svnversion.h: FORCE
	$(PERL) $(srcdir)/make-version.pl $(srcdir)

