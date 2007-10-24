AC_PREREQ(2.60)
AC_INIT([flowgrind],[0.1],[daniel.schaffrath@mac.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror dist-bzip2])

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

AC_C_CONST
AC_C_INLINE

AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([uname])

AC_CHECK_LIB([m], [log])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [socket])
AC_CHECK_LIB([resolv], [herror])
AC_CHECK_LIB([rt], [nanosleep])
AC_CHECK_LIB([fasttime], [fasttime_init_context])
AC_CHECK_LIB([tsci2], [tsci2_init])

AC_HEADER_STDC
AC_CHECK_HEADERS([ \
        syslog.h \
        sys/time.h \
        sys/socket.h \
        sys/param.h \
        sys/ioctl.h \
        netinet/in.h \
        netdb.h \
        limits.h \
        fcntl.h \
        arpa/inet.h \
        fasttime.h \
        float.h \
        tsci2.h])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
        Makefile
        src/Makefile])

AC_OUTPUT
