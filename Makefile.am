SUBDIRS = src
EXTRA_DIST = configure make-version.pl
CLEANFILES = svnversion.h
BUILT_SOURCES = svnversion.h

FORCE:

svnversion.h: FORCE
	$(PERL) $(srcdir)/make-version.pl $(srcdir)

dist_man1_MANS = man/flowgrind.man \
		 man/flowgrindd.man \
		 man/flowgrind-stop.man

dist_noinst_DATA = COPYING.thrulay

