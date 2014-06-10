AC_INIT([Flowgrind],[0.7.1],[https://github.com/flowgrind/flowgrind/issues],[flowgrind],[https://www.flowgrind.net])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror dist-bzip2])
AC_PREREQ(2.61)

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_MAKE_SET
AC_PATH_TOOL(PERL, perl)

# Checks for host-system types
AC_CANONICAL_HOST
case $host in
    *darwin*)
        AC_DEFINE([__DARWIN__], [1], [Darwin])
        AC_DEFINE([_BSD_SOCKLEN_T_], [], [Need this under Darwin so that \
            socklen_t will be defined in <sys/socket.h>])
        # if Macport is used
        if test -d /opt/local/lib ; then
            LDFLAGS="-L/opt/local/lib $LDFLAGS"
        fi
        if test -d /opt/local/include ; then
            CFLAGS="-I/opt/local/include $CFLAGS"
        fi
        ;;
    *freebsd*)
        AC_DEFINE([__FREEBSD__], [1], [FreeBSD])
        LDFLAGS="-L/usr/local/lib $LDFLAGS"
        CFLAGS="-I/usr/local/include $CFLAGS"
        ;;
    *linux*)
        AC_DEFINE([__LINUX__], [1], [Linux])
        ;;
esac

AC_C_CONST
AC_C_INLINE

AC_GNU_SOURCE

AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME

AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_STDC

AC_STRUCT_TM

AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT8_T
AC_TYPE_UINT32_T
AC_TYPE_INT32_T
AC_TYPE_UNSIGNED_LONG_LONG_INT

AC_CHECK_FUNCS([ \
    bzero \
    memset \
    pselect \
    socket \
    strchr \
    strerror \
    uname \
    asprintf \
    strdup \
], [], [AC_MSG_ERROR(required function not found.)]
)

AC_CHECK_HEADERS([ \
    arpa/inet.h \
    errno.h \
    fcntl.h \
    fenv.h \
    float.h \
    limits.h \
    math.h \
    netdb.h \
    netinet/in.h \
    netinet/in_systm.h \
    netinet/tcp.h \
    pthread.h \
    signal.h \
    stdarg.h \
    stdio.h \
    stdlib.h \
    string.h \
    sys/ioctl.h \
    syslog.h \
    sys/param.h \
    sys/time.h \
    sys/uio.h \
    sys/utsname.h \
    time.h \
], [], [AC_MSG_ERROR(required header not found.)]
)

AC_CHECK_HEADERS(net/if.h, [], [AC_MSG_ERROR(required header not found.)], [
    #include <stdio.h>
    #include <stdlib.h>
    #include <stddef.h>
    #include <sys/types.h>
    #include <sys/socket.h>
])

AC_CHECK_HEADERS(netinet/if_ether.h netinet/ip.h, [], [AC_MSG_ERROR(required header not found.)], [
    #include <stdio.h>
    #include <stdlib.h>
    #include <stddef.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/in_systm.h>
])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile \
    src/Makefile \
])

AC_SEARCH_LIBS([log], [m])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([pthread_create], [pthread])

AC_SUBST(LIBS)

AC_ARG_ENABLE(debug,[AS_HELP_STRING(--enable-debug, enable debugging output and symbols [[default: no]] )])

if test "$enable_debug" = yes ; then
    AC_DEFINE(DEBUG, [1], [Use debugging])
fi

AC_ARG_ENABLE(pcap,[AS_HELP_STRING(--enable-pcap, enable lipcap for packet capturing [[default: yes]] )])
AS_IF([ test "x$enable_pcap" != "xno"], [
    AC_CHECK_HEADER(pcap.h,
        AC_CHECK_LIB([pcap], pcap_open_live, [LINKABLE_LIBPCAP=1 AC_DEFINE(HAVE_LIBPCAP, 1, [Define to 1 if \
                      you have the pcap library (-lpcap).])],
        AC_MSG_NOTICE([*** Could not find libpcap: will compile without optional traffic dump feature. ***]),[-lpcap]),
        AC_MSG_NOTICE([*** Header file pcap.h not found: will compile without optional traffic dump feature. ***])
    )

    if test -z "$PCAP_CONFIG"; then
        AC_PATH_PROG(PCAP_CONFIG, pcap-config, no)
    fi

    if test "x$PCAP_CONFIG" = "xno"; then
        AC_MSG_NOTICE(pcap-config not found in path.)
    else
        PCAP_CFLAGS=`$PCAP_CONFIG --cflags`
        PCAP_LDADD=`$PCAP_CONFIG --libs`

        AC_SUBST(PCAP_CFLAGS)
        AC_SUBST(PCAP_LDADD)
    fi
])
AM_CONDITIONAL([USE_LIBPCAP], [test "x$enable_pcap" != "xno" -a "$LINKABLE_LIBPCAP" -eq 1])

AC_ARG_ENABLE(gsl,[AS_HELP_STRING(--enable-gsl, enable GNU Scientific Library [[default: yes]] )])
AS_IF([ test "x$enable_gsl" != "xno"], [
    AC_CHECK_HEADER(gsl/gsl_rng.h,
        AC_CHECK_LIB([gsl], gsl_rng_alloc, [AC_DEFINE(HAVE_LIBGSL, 1, [Define to 1 if you have the gsl library (-lgsl).])],
        AC_MSG_NOTICE([*** Could not find libgsl: will compile without optional trafgen distributions. ***]),[-lgslcblas]),
        AC_MSG_NOTICE([*** Header file gsl_rng.h not found: will compile without optional trafgen distributions. ***])
    )

    if test -z "$GSL_CONFIG"; then
        AC_PATH_PROG(GSL_CONFIG, gsl-config, no)
    fi

    if test "x$GSL_CONFIG" = "xno"; then
        AC_MSG_NOTICE(gsl-config not found in path.)
    else
        GSL_CFLAGS=`$GSL_CONFIG --cflags`
        GSL_LDADD=`$GSL_CONFIG --libs`

        AC_SUBST(GSL_CFLAGS)
        AC_SUBST(GSL_LDADD)
    fi
])

if test -z "$CURL_CONFIG"; then
    AC_PATH_TOOL(CURL_CONFIG, curl-config, no)
fi

if test "x$CURL_CONFIG" = "xno" ; then
    AC_MSG_ERROR(required curl-config not found in path.)
fi

CURL_CFLAGS=`$CURL_CONFIG --cflags`
CURL_LDADD=`$CURL_CONFIG --libs`

AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LDADD)

if test -z "$XMLRPC_C_CONFIG"; then
    AC_PATH_TOOL(XMLRPC_C_CONFIG, xmlrpc-c-config, no)
fi

if test "x$XMLRPC_C_CONFIG" = "xno"; then
    AC_MSG_ERROR([xmlrpc-c-config not found in path.])
fi

if ! $XMLRPC_C_CONFIG --features | grep "curl-client" > /dev/null; then
    AC_MSG_ERROR([xmlrpc-c needs to be compiled with curl-client enabled.])
fi

if ! $XMLRPC_C_CONFIG --features | grep "abyss-server" > /dev/null; then
    AC_MSG_ERROR([xmlrpc-c needs to be compiled with abyss-server enabled.])
fi

XMLRPC_C_VERSION=`$XMLRPC_C_CONFIG --version`

AC_CHECK_MEMBERS(struct xmlrpc_curl_xportparms.dont_advertise,,,[
    #include <xmlrpc-c/client.h>
    #include <xmlrpc-c/transport.h>
])
AC_MSG_NOTICE([xmlrpc-c found in version $XMLRPC_C_VERSION])
AC_DEFINE_UNQUOTED([XMLRPC_C_VERSION], [$XMLRPC_C_VERSION], [the current xmlrpc-c version])

XMLRPC_C_CLIENT_CFLAGS=`$XMLRPC_C_CONFIG client --cflags`
XMLRPC_C_CLIENT_LDADD=`$XMLRPC_C_CONFIG client --ldadd`
XMLRPC_C_SERVER_CFLAGS=`$XMLRPC_C_CONFIG abyss-server --cflags`
XMLRPC_C_SERVER_LDADD=`$XMLRPC_C_CONFIG abyss-server --ldadd`

AC_SUBST(XMLRPC_C_CLIENT_CFLAGS)
AC_SUBST(XMLRPC_C_CLIENT_LDADD)
AC_SUBST(XMLRPC_C_SERVER_CFLAGS)
AC_SUBST(XMLRPC_C_SERVER_LDADD)

AC_OUTPUT
