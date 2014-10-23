#
# Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
#
# This file is part of Flowgrind.
#
# Flowgrind is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Flowgrind is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Flowgrind.  If not, see <http://www.gnu.org/licenses/>.
#

# Initialization & setup
AC_INIT([Flowgrind], [0.7.5], [https://github.com/flowgrind/flowgrind/issues],
	[flowgrind], [http://www.flowgrind.net])
AC_COPYRIGHT([Copyright (C) 2007 - 2014 Flowgrind authors])

AC_PREREQ([2.61])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror no-dist subdir-objects 1.10])

# Files to generate
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile])

# Checking for host-system
AC_CANONICAL_HOST
AS_CASE([$host],
	[*darwin*],
	[AC_DEFINE([__DARWIN__], [1], [This is an OS X system.])
	 AC_DEFINE([_BSD_SOCKLEN_T_], [],
		[Needed under Darwin so that socklen_t will be defined in <sys/socket.h>.])

	 # Check for Macports
	 AS_IF([test -d /opt/local/lib],
		[LDFLAGS="${LDFLAGS} -L/opt/local/lib"])
	 AS_IF([test -d /opt/local/include],
		[CPPFLAGS="${CPPFLAGS} -I/opt/local/include"])
	],

	[*freebsd*],
	[AC_DEFINE([__FREEBSD__], [1], [This is a FreeBSD system.])

	 AS_IF([test -d /usr/local/lib],
		[LDFLAGS="${LDFLAGS} -L/usr/local/lib"])
	 AS_IF([test -d /usr/local/include],
		[CPPFLAGS="${CPPFLAGS} -I/usr/local/include"])
	],

	[*linux*],
	[AC_DEFINE([__LINUX__], [1], [This is a GNU/Linux system.])],
	[AC_MSG_WARN([Unknown system. Hoping this is a GNU/Linux-compatible system.])])

# Checking for C compiler characteristics & Posix variants
AC_PROG_CC([cc gcc clang])
AM_PROG_CC_C_O
AC_PROG_CPP
AC_LANG([C])
AC_USE_SYSTEM_EXTENSIONS
AC_C_CONST
AC_C_INLINE

# Checking for command line argument --enable-debug
AC_MSG_CHECKING([whether to enable debugging output])
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [turn on debugging output])],
	[AS_IF([test "x$enable_debug" = "xyes"],
		[AC_DEFINE([DEBUG], [1],
			[Define to 1 if debugging output should be enabled.])
		],

		[test "x$enable_debug" != "xno"],
		[enable_debug=no;
		 AC_MSG_WARN([invalid argument supplied to --enable-debug])
		])
	],
    [enable_debug=no])
AC_MSG_RESULT([$enable_debug])

# Checking for command line argument --enable-assert
AC_MSG_CHECKING([whether to enable assertions])
AC_ARG_ENABLE([assert],
	[AS_HELP_STRING([--enable-assert], [turn on assertions])],
	[AS_IF([test "x$enable_assert" = "xno"],
		[AC_DEFINE([NDEBUG], [1],
			[Define to 1 if assertions should be disabled.])
		],

		[test "x$enable_assert" != "xyes"],
		[enable_assert=no;
		 AC_MSG_WARN([invalid argument supplied to --enable-assert])
		])
	],
    [enable_assert=no;
	 AC_DEFINE([NDEBUG], [1],
		[Define to 1 if assertions should be disabled.])
	])
AC_MSG_RESULT([$enable_assert])

# Checking for command line argument --without-doxygen
AC_ARG_WITH([doxygen],
	[AS_HELP_STRING([--without-doxygen],
		[disable doxygen feature to generate API documentation])
	])

AS_IF([test "x$with_doxygen" != "xno"],
	[AC_PATH_TOOL([DOXYGEN], [doxygen])],
	[DOXYGEN=""])

AS_IF([test -n "$DOXYGEN"],
	[AC_DEFINE([HAVE_DOXYGEN], [1],
		[Define to 1 if the system has doxygen installed.])
	],
	[AS_IF([test "x$with_doxygen" = "xyes"],
		[AC_MSG_ERROR([doxygen requested but not found])])
	])
AM_CONDITIONAL([USE_DOXYGEN],
	[test "x$with-doxygen" != "xno" -a -n "$DOXYGEN"])

# Checking for command line argument --without-pcap
AC_ARG_WITH([pcap],
	[AS_HELP_STRING([--without-pcap], [disable packet capturing feature])])

AS_IF([test "x$with_pcap" != "xno"],
	[AC_CHECK_HEADER([pcap/pcap.h],
		[AC_CHECK_LIB([pcap], [pcap_create],
			[have_pcap=yes],
			[have_pcap=no;
			 AC_MSG_WARN([libpcap not found. No support for traffic dump])
			],
			[-lpcap])
		],
		[have_pcap=no;
		 AC_MSG_WARN([pcap.h not found. No support for traffic dump])
		])
	],
	[have_pcap=no])

AS_IF([test "x$have_pcap" = "xyes"],
	[AC_DEFINE([HAVE_LIBPCAP], [1],
		[Define to 1 if the system has libpcap installed (-lpcap).])

	 AS_IF([test -z "$PCAP_CONFIG"],
		[AC_PATH_TOOL([PCAP_CONFIG], [pcap-config], [no])])

	 AS_IF([test "x$PCAP_CONFIG" = "xno"],
		[AC_MSG_NOTICE([pcap-config not found in path])],
		[PCAP_CFLAGS=`$PCAP_CONFIG --cflags`
		 PCAP_LDADD=`$PCAP_CONFIG --libs`

		 AC_SUBST([PCAP_CFLAGS])
		 AC_SUBST([PCAP_LDADD])
		])
	],
	[AS_IF([test "x$with_pcap" = "xyes"],
		[AC_MSG_ERROR([libpcap requested but not found])])
	])
AM_CONDITIONAL([USE_LIBPCAP],
	[test "x$with_pcap" != "xno" -a "x$have_pcap" = "xyes"])

# Checking for command line argument --without-gsl
AC_ARG_WITH([gsl],
	[AS_HELP_STRING([--without-gsl],
		[disable stochastic traffic generation feature])])

AS_IF([test "x$with_gsl" != "xno"],
	[AC_CHECK_HEADER([gsl/gsl_rng.h],
		[AC_CHECK_LIB([gsl], [gsl_rng_alloc],
			[have_gsl=yes],
			[have_gsl=no;
			 AC_MSG_WARN([libgsl not found. No stochastic traffic generation])
			],
			[-lgslcblas])
		],
		[have_gsl=no;
		 AC_MSG_WARN([gsl_rng.h not found. No stochastic traffic generation])
		])
	],
	[have_gsl=no])

AS_IF([test "x$have_gsl" = "xyes"],
	[AC_DEFINE([HAVE_LIBGSL], [1],
		[Define to 1 if the system has libgsl installed (-lgsl).])

	 AS_IF([test -z "$GSL_CONFIG"],
		[AC_PATH_TOOL([GSL_CONFIG], [gsl-config], [no])])

	 AS_IF([test "x$GSL_CONFIG" = "xno"],
		[AC_MSG_NOTICE([gsl-config not found in path])],
		[GSL_CFLAGS=`$GSL_CONFIG --cflags`
		 GSL_LDADD=`$GSL_CONFIG --libs`

		 AC_SUBST([GSL_CFLAGS])
		 AC_SUBST([GSL_LDADD])
		])
	],
	[AS_IF([test "x$with_gsl" = "xyes"],
		[AC_MSG_ERROR([libgsl requested but not found])])
	])
AM_CONDITIONAL([USE_LIBGSL],
	[test "x$with_gsl" != "xno" -a "x$have_gsl" = "xyes"])

# Checking fot header files
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_CHECK_HEADERS(
	[arpa/inet.h \
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
	 stdio.h \
	 sys/ioctl.h \
	 syslog.h \
	 sys/param.h \
	 sys/uio.h \
	 sys/utsname.h \
	], [], [AC_MSG_ERROR([required header not found])])

AC_CHECK_HEADERS(
	[sys/socket.h \
	 pthread_np.h \
	])

AC_CHECK_HEADERS(
	[sys/cpuset.h], [], [],
	[[#include <sys/param.h>]])

AC_CHECK_HEADERS([net/if.h], [],
	[AC_MSG_ERROR([required header not found])],
	[[#include <stdio.h>
	  #include <stdlib.h>
	  #include <stddef.h>
	  #include <sys/socket.h>
	]])

AC_CHECK_HEADERS([netinet/if_ether.h netinet/ip.h], [],
	[AC_MSG_ERROR([required header not found])],
	[[#include <stdio.h>
	  #include <stdlib.h>
	  #include <stddef.h>
	  #include <sys/types.h>
	  #include <sys/socket.h>
	  #include <netinet/in.h>
	  #include <netinet/in_systm.h>
	]])

# Checking for libraries
AC_SEARCH_LIBS([log], [m])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([clock_gettime], [rt])

# Checking for types
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT8_T
AC_TYPE_UINT32_T
AC_TYPE_INT32_T
AC_TYPE_UNSIGNED_LONG_LONG_INT

# Checking for declarations
AC_CHECK_DECL([IP_MTU_DISCOVER],
	[AC_DEFINE([HAVE_SO_IP_MTU_DISCOVER], [1],
		[Define to 1 if system has IP_MTU_DISCOVER as socket option.])],
	[], [[#include <netinet/ip.h>]])
AC_CHECK_DECL([TCP_CORK],
	[AC_DEFINE([HAVE_SO_TCP_CORK], [1],
		[Define to 1 if system has TCP_CORK as socket option.])],
	[], [[#include <netinet/tcp.h>]])
AC_CHECK_DECL([TCP_CONGESTION],
	[AC_DEFINE([HAVE_SO_TCP_CONGESTION], [1],
		[Define to 1 if system has TCP_CONGESTION as socket option.])],
	[], [[#include <netinet/tcp.h>]])
AC_CHECK_DECL([TCP_INFO],
	[AC_DEFINE([HAVE_SO_TCP_INFO], [1],
		[Define to 1 if system has TCP_INFO as socket option.])],
	[], [[#include <netinet/tcp.h>]])

# Checking for structures
AC_STRUCT_TM

# Checking for struct cpuset_t
AC_MSG_CHECKING([for struct cpuset_t])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[#if defined HAVE_SYS_CPUSET_H
		  #include <sys/param.h>
		  #include <sys/cpuset.h>
		  #endif
		]],
		[[cpuset_t cpuset;]])
	],
	[have_cpuset_t=yes;
	 AC_DEFINE([HAVE_CPUSET_T], [1],
		[Define to 1 if the system has struct cpuset_t.])
	],
	[have_cpuset_t=no])
AC_MSG_RESULT([$have_cpuset_t])

# Checking for struct cpu_set_t
AC_MSG_CHECKING([for struct cpu_set_t])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <sched.h>]],
		[[cpu_set_t cpuset;]])
	],
	[have_cpu_set_t=yes;
	 AC_DEFINE([HAVE_CPU_SET_T], [1],
		[Define to 1 if the system has struct cpu_set_t.])
	],
	[have_cpu_set_t=no])
AC_MSG_RESULT([$have_cpu_set_t])

# Checking for struct tcp_info
AC_MSG_CHECKING([for struct tcp_info])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <netinet/tcp.h>]],
		[[struct tcp_info ti;]])
	],
	[have_tcp_info=yes;
	 AC_DEFINE([HAVE_TCP_INFO], [1],
		[Define to 1 if the system has struct tcp_info.])
	],
	[have_tcp_info=no])
AC_MSG_RESULT([$have_tcp_info])

# Checking for enum tcp_ca_state
AC_MSG_CHECKING([for enum tcp_ca_state])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <netinet/tcp.h>]],
		[[enum tcp_ca_state state;]])
	],
	[have_tcp_ca_state=yes;
	 AC_DEFINE([HAVE_TCP_CA_STATE], [1],
		[Define to 1 if the system has enum tcp_ca_state.])
	],
	[have_tcp_ca_state=no])
AC_MSG_RESULT([$have_tcp_ca_state])

# Checking for functions
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(
	[bzero \
	 memset \
	 pselect \
	 socket \
	 strchr \
	 strerror \
	 uname \
	 asprintf \
	 strdup \
	], [], [AC_MSG_ERROR([required function not found])])

# Checking for function clock_gettime & clock_get_time
AC_CHECK_FUNC([clock_gettime],
	[have_clock_gettime=yes;
	 AC_DEFINE([HAVE_CLOCK_GETTIME], [1],
		[Define to 1 if the system has clock_gettime.])
	])

AS_IF([test "x$have_clock_gettime" != "xyes"],
	[AC_MSG_CHECKING([for clock_get_time])
	 AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[#include <mach/mach.h>
			  #include <mach/clock.h>
			]],
			[[clock_serv_t cclock; mach_timespec_t mts;
			  host_get_clock_service(mach_host_self(), REALTIME_CLOCK, &cclock);
			  clock_get_time(cclock, &mts);
			]])
		],
		[have_clock_get_time=yes;
		 AC_DEFINE([HAVE_CLOCK_GET_TIME], [1],
			[Define to 1 if the system has clock_get_time.])
		],
		[have_clock_get_time=no])
	 AC_MSG_RESULT([$have_clock_get_time])
	])

AS_IF([test "x$have_clock_gettime" != "xyes" -a \
			"x$have_clock_get_time" != "xyes"],
	[AC_MSG_ERROR([required function not found])])

# Checking for pthread_barrier
AC_CHECK_FUNCS(
	[pthread_barrier_init \
	 pthread_barrier_wait \
	 pthread_barrier_destroy \
	],
	[have_pthread_barrier=yes;
	 AC_DEFINE([HAVE_PTHREAD_BARRIER], [1],
		[Define to 1 if the system has pthread_barrier.])
	])
AM_CONDITIONAL([USE_FG_PTHREAD_BARRIER],
	[test "x$have_pthread_barrier" != "xyes"])

# Checking for function pthread_getaffinity_np & thread_policy_get
AC_MSG_CHECKING([for pthread_getaffinity_np])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <pthread.h>
		  #if defined HAVE_PTHREAD_NP_H
		  #include <pthread_np.h>
		  #endif
		  #if defined HAVE_SYS_CPUSET_H
		  #include <sys/param.h>
		  #include <sys/cpuset.h>
		  #endif
		  #if !defined(HAVE_CPU_SET_T)
		  typedef cpuset_t cpu_set_t;
		  #endif
		]],
		[[cpu_set_t cpuset; CPU_ZERO(&cpuset);
		  pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
		]])
	],
	[have_pthread_getaffinity_np=yes;
	 AC_DEFINE([HAVE_PTHREAD_AFFINITY_NP], [1],
		[Define to 1 if the system has pthread_getaffinity_np.])
	],
	[have_pthread_getaffinity_np=no])
AC_MSG_RESULT([$have_pthread_getaffinity_np])

AS_IF([test "x$have_pthread_getaffinity_np" != "xyes"],
	[AC_MSG_CHECKING([for thread_policy_get])
	 AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[#include <mach/mach.h>
			  #include <mach/mach_time.h>
			]],
			[[thread_affinity_policy_data_t policy;
			  mach_msg_type_number_t count = THREAD_AFFINITY_POLICY_COUNT;
			  boolean_t	get_default = FALSE;
			  thread_policy_get(mach_thread_self(), THREAD_AFFINITY_POLICY,
								(thread_policy_t) &policy, &count, &get_default);
			]])
		],
		[have_thread_policy_get=yes;
		 AC_DEFINE([HAVE_THREAD_POLICY], [1],
			[Define to 1 if the system has thread_policy_get.])
		],
		[have_thread_policy_get=no])
	 AC_MSG_RESULT([$have_thread_policy_get])
	])

AS_IF([test "x$have_pthread_getaffinity_np" != "xyes" -a \
			"x$have_thread_policy_get" != "xyes"],
	[AC_MSG_ERROR([required function not found])])

# Checking for CURL library
AS_IF([test -z "$CURL_CONFIG"],
	[AC_PATH_TOOL([CURL_CONFIG], [curl-config], [no])])

AS_IF([test "x$CURL_CONFIG" = "xno"],
	[AC_MSG_ERROR([required curl-config not found in path])])

CURL_CFLAGS=`$CURL_CONFIG --cflags`
CURL_LDADD=`$CURL_CONFIG --libs`

AC_SUBST([CURL_CFLAGS])
AC_SUBST([CURL_LDADD])

# Checking for xmlrpc-c library
AS_IF([test -z "$XMLRPC_C_CONFIG"],
	[AC_PATH_TOOL([XMLRPC_C_CONFIG], [xmlrpc-c-config], [no])])

AS_IF([test "x$XMLRPC_C_CONFIG" = "xno"],
	[AC_MSG_ERROR([required xmlrpc-c-config not found in path])])

AS_IF([! $XMLRPC_C_CONFIG --features | grep "curl-client" > /dev/null],
	[AC_MSG_ERROR([xmlrpc-c needs to be compiled with curl-client enabled])])

AS_IF([! $XMLRPC_C_CONFIG --features | grep "abyss-server" > /dev/null],
	[AC_MSG_ERROR([xmlrpc-c needs to be compiled with abyss-server enabled])])

XMLRPC_C_VERSION=`$XMLRPC_C_CONFIG --version`
AC_MSG_NOTICE([xmlrpc-c found in version $XMLRPC_C_VERSION])
AC_DEFINE_UNQUOTED([XMLRPC_C_VERSION],
	[$XMLRPC_C_VERSION], [the current xmlrpc-c version])

AC_CHECK_MEMBERS([struct xmlrpc_curl_xportparms.dont_advertise], [], [],
	[[#include <xmlrpc-c/client.h>
	  #include <xmlrpc-c/transport.h>
	]])

XMLRPC_C_CLIENT_CFLAGS=`$XMLRPC_C_CONFIG client --cflags`
XMLRPC_C_CLIENT_LDADD=`$XMLRPC_C_CONFIG client --ldadd`
XMLRPC_C_SERVER_CFLAGS=`$XMLRPC_C_CONFIG abyss-server --cflags`
XMLRPC_C_SERVER_LDADD=`$XMLRPC_C_CONFIG abyss-server --ldadd`

AC_SUBST([XMLRPC_C_CLIENT_CFLAGS])
AC_SUBST([XMLRPC_C_CLIENT_LDADD])
AC_SUBST([XMLRPC_C_SERVER_CFLAGS])
AC_SUBST([XMLRPC_C_SERVER_LDADD])

# Outputting files
AC_PROG_MAKE_SET
AC_OUTPUT
