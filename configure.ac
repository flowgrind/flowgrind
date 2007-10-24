AC_INIT([flowgrind], [0.1], [daniel.schaffrath@mac.com])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PATH_PROG(PERL, perl)

# Checks for host-system types
AC_CANONICAL_HOST
case $host in
  *darwin*)
    AC_DEFINE([__DARWIN__], [1], [Darwin])
    AC_DEFINE([_BSD_SOCKLEN_T_], [], [Need this under Darwin so that \
    	socklen_t will be defined in <sys/socket.h>])
    ;;
  *freebsd*)
    AC_DEFINE([__FREEBSD__], [1], [FreeBSD])
    ;;
  *linux*)
    AC_DEFINE([__LINUX__], [1], [Linux])
    ;;
  *solaris*)
    AC_DEFINE([__SOLARIS__], [1], [Solaris])
    ;;
esac

# Checks for libraries.
AC_CHECK_LIB([m], [log])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [socket])
AC_CHECK_LIB([resolv], [herror])
AC_CHECK_LIB([rt], [nanosleep])
AC_CHECK_LIB([fasttime], [fasttime_init_context])
AC_CHECK_LIB([tsci2], [tsci2_init])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fasttime.h float.h tsci2.h])

AC_OUTPUT([Makefile src/Makefile])
