
AC_INIT([flowgrind],[0.5],[flowgrind@umic-mesh.net])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror dist-bzip2])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AM_C_PROTOTYPES
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
AC_TYPE_INT8_T
AC_TYPE_UINT32_T
AC_TYPE_INT32_T
AC_TYPE_UNSIGNED_LONG_LONG_INT

AC_CHECK_FUNCS([ \
	bzero \
	getopt_long \
	gettimeofday \
	memset \
	select \
	socket \
	strchr \
	strerror \
	uname \
])


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
        float.h \
])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([ \
        Makefile
        src/Makefile \
])


AC_CHECK_LIB([m], [log])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [socket])
AC_CHECK_LIB([resolv], [herror])
AC_CHECK_LIB([rt], [nanosleep])

AC_ARG_ENABLE(debug,[AS_HELP_STRING(--enable-debug, enable debugging output and symbols [[default: no]] )])

if test "$enable_debug" = yes ; then
	AC_DEFINE(DEBUG, [1], [Use debugging])
	CFLAGS="-ggdb3 $CFLAGS"
else
	CFLAGS="-O3 $CFLAGS"
fi

AC_ARG_ENABLE(pcap,[AS_HELP_STRING(--enable-pcap, enable lipcap for packet capturing [[default: yes]] )])
AS_IF([ test "x$enable_pcap" != "xno"], [
        AC_CHECK_HEADER(pcap.h,
                AC_CHECK_LIB([pcap], pcap_open_live, [AC_DEFINE(HAVE_LIBPCAP, 1, [Define to 1 if you have the pcap library (-pcap).])],
                AC_MSG_NOTICE([*** Could not find libpcap: will compile without optional traffic dump feature. ***]),[-pcap]),
                AC_MSG_NOTICE([*** Header file pcap.h not found: will compile without optional traffic dump. ***]))

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

AC_ARG_ENABLE(gsl,[AS_HELP_STRING(--enable-gsl, enable GNU Scientific Library [[default: yes]] )])
AS_IF([ test "x$enable_gsl" != "xno"], [
	AC_CHECK_HEADER(gsl/gsl_rng.h,
   		AC_CHECK_LIB([gsl], gsl_rng_alloc, [AC_DEFINE(HAVE_LIBGSL, 1, [Define to 1 if you have the gsl library (-lgsl).])],
          	AC_MSG_NOTICE([*** Could not find libgsl: will compile without optional trafgen distributions. ***]),[-lgslcblas]),
     		AC_MSG_NOTICE([*** Header file gsl_rng.h not found: will compile without optional trafgen distributions. ***]))
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
        AC_PATH_PROG(CURL_CONFIG, curl-config, no)
fi

if test "x$CURL_CONFIG" = "xno" ; then
        AC_MSG_ERROR(required curl-config not found in path.)
fi

CURL_CFLAGS=`$CURL_CONFIG --cflags`
CURL_LDADD=`$CURL_CONFIG --libs`

AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LDADD)

if test -z "$XMLRPC_C_CONFIG"; then
        AC_PATH_PROG(XMLRPC_C_CONFIG, xmlrpc-c-config, no)
fi
  
if test "x$XMLRPC_C_CONFIG" = "xno"; then
	AC_MSG_ERROR(xmlrpc-c-config not found in path.)
fi

if ! $XMLRPC_C_CONFIG --features | grep "curl-client" > /dev/null; then
	AC_MSG_ERROR([xmlrpc-c needs to be compiled with curl-client enabled.])
fi

if ! $XMLRPC_C_CONFIG --features | grep "abyss-server" > /dev/null; then
	AC_MSG_ERROR([xmlrpc-c needs to be compiled with abyss-server enabled.])
fi

XMLRPC_C_CLIENT_CFLAGS=`xmlrpc-c-config client --cflags`
XMLRPC_C_CLIENT_LDADD=`xmlrpc-c-config client --ldadd`
XMLRPC_C_SERVER_CFLAGS=`xmlrpc-c-config abyss-server --cflags`
XMLRPC_C_SERVER_LDADD=`xmlrpc-c-config abyss-server --ldadd`

AC_SUBST(XMLRPC_C_CLIENT_CFLAGS)
AC_SUBST(XMLRPC_C_CLIENT_LDADD)
AC_SUBST(XMLRPC_C_SERVER_CFLAGS)
AC_SUBST(XMLRPC_C_SERVER_LDADD)

AC_OUTPUT
