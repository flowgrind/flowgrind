
AC_DEFUN([AC_ADD_DASH_L],
[$1="$$1 -L$2"
case "$host_os" in
  solaris*)
    $1="$$1 -R$2"
  ;;
esac
])

AC_DEFUN([AC_PCAP_CHECK],
[
	if test -z "$pcap_dir"
	then
	  # Pcap header checks
	  # XXX need to set a var AC_CHECK_HEADER(pcap.h,,)

	  #
	  # The user didn't specify a directory in which libpcap resides;
	  # we assume that the current library search path will work,
	  # but we may have to look for the header in a "pcap"
	  # subdirectory of "/usr/include" or "/usr/local/include",
	  # as some systems apparently put "pcap.h" in a "pcap"
	  # subdirectory, and we also check "$prefix/include" - and
	  # "$prefix/include/pcap", in case $prefix is set to
	  # "/usr/include" or "/usr/local/include".
	  #
	  # XXX - should we just add "$prefix/include" to the include
	  # search path and "$prefix/lib" to the library search path?
	  #
	  AC_MSG_CHECKING(for extraneous pcap header directories)
	  found_pcap_dir=""
	  pcap_dir_list="/usr/include/pcap $prefix/include/pcap $prefix/include"
	  if test "x$ac_cv_enable_usr_local" = "xyes" ; then
	    pcap_dir_list="$pcap_dir_list /usr/local/include/pcap"
	  fi
	  for pcap_dir in $pcap_dir_list
	  do
	    if test -d $pcap_dir ; then
		if test x$pcap_dir != x/usr/include -a x$pcap_dir != x/usr/local/include ; then
		    CFLAGS="$CFLAGS -I$pcap_dir"
		    CPPFLAGS="$CPPFLAGS -I$pcap_dir"
		fi
		found_pcap_dir=" $found_pcap_dir -I$pcap_dir"
		break
	    fi
	  done

	  if test "$found_pcap_dir" != "" ; then
	    AC_MSG_RESULT(found --$found_pcap_dir added to CFLAGS)
	  else
	    AC_MSG_RESULT(not found)
	  fi
	else
	  #
	  # The user specified a directory in which libpcap resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a libpcap in a directory that's
	  # already in CFLAGS, CPPFLAGS, or LDFLAGS, this won't
	  # make us find the version in the specified directory,
	  # as the compiler and/or linker will search that other
	  # directory before it searches the specified directory.
	  #
	  CFLAGS="$CFLAGS -I$pcap_dir/include"
	  CPPFLAGS="$CPPFLAGS -I$pcap_dir/include"
	  AC_ADD_DASH_L(LDFLAGS, $pcap_dir/lib)
	fi

	# Pcap header check
	AC_CHECK_HEADER(pcap.h,, 
	    AC_MSG_ERROR([[Header file pcap.h not found; if you installed libpcap
from source, did you also do \"make install-incl\", and if you installed a
binary package of libpcap, is there also a developer's package of libpcap,
and did you also install that package?]]))

	#
	# Check to see if we find "pcap_open_live" in "-lpcap".
	# Also check for various additional libraries that libpcap might
	# require.
	#
	AC_CHECK_LIB(pcap, pcap_open_live,
	  [
	    PCAP_LIBS=-lpcap
	    AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap library])
	  ], [
	    ac_wireshark_extras_found=no
	    ac_save_LIBS="$LIBS"
	    for extras in "-lcfg -lodm" "-lpfring"
	    do
		AC_MSG_CHECKING([for pcap_open_live in -lpcap with $extras])
		LIBS="-lpcap $extras"
		#
		# XXX - can't we use AC_CHECK_LIB here?
		#
		AC_TRY_LINK(
		    [
#	include <pcap.h>
		    ],
		    [
	pcap_open_live(NULL, 0, 0, 0, NULL);
		    ],
		    [
			ac_wireshark_extras_found=yes
			AC_MSG_RESULT([yes])
			PCAP_LIBS="-lpcap $extras"
			AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap library])
		    ],
		    [
			AC_MSG_RESULT([no])
		    ])
		if test x$ac_wireshark_extras_found = xyes
		then
		    break
		fi
	    done
	    if test x$ac_wireshark_extras_found = xno
	    then
		AC_MSG_ERROR([Can't link with library libpcap.])
	    fi
	    LIBS=$ac_save_LIBS
	  ], $SOCKET_LIBS $NSL_LIBS)
	AC_SUBST(PCAP_LIBS)

	#
	# Check whether various variables and functions are defined by
	# libpcap.
	#
	ac_save_LIBS="$LIBS"
	AC_MSG_CHECKING(whether pcap_version is defined by libpcap)
	LIBS="$PCAP_LIBS $SOCKET_LIBS $NSL_LIBS $LIBS"
	AC_TRY_LINK(
	   [
#	include <stdio.h>
	extern char *pcap_version;
	   ],
	   [
	printf ("%s\n", pcap_version);
	   ],
	   ac_cv_pcap_version_defined=yes,
	   ac_cv_pcap_version_defined=no,
	   [echo $ac_n "cross compiling; assumed OK... $ac_c"])
	if test "$ac_cv_pcap_version_defined" = yes ; then
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_PCAP_VERSION, 1, [Define if libpcap version is known])
	else
		AC_MSG_RESULT(no)
	fi
	AC_CHECK_FUNCS(pcap_open_dead pcap_freecode pcap_breakloop)
	#
	# Later versions of Mac OS X 10.3[.x] ship a pcap.h that
	# doesn't define pcap_if_t but ship an 0.8[.x] libpcap,
	# so the library has "pcap_findalldevs()", but pcap.h
	# doesn't define "pcap_if_t" so you can't actually *use*
	# "pcap_findalldevs()".
	#
	# That even appears to be true of systems shipped with
	# 10.3.4, so it doesn't appear only to be a case of
	# Software Update not updating header files.
	#
	# (You can work around this by installing the 0.8 header
	# files.)
	#
	AC_CACHE_CHECK([whether pcap_findalldevs is present and usable],
	  [ac_cv_func_pcap_findalldevs],
	  [
	    AC_LINK_IFELSE(
	      [
		AC_LANG_SOURCE(
		  [[
		    #include <pcap.h>
		    main()
		    {
		      pcap_if_t *devpointer;
		      char errbuf[1];

		      pcap_findalldevs(&devpointer, errbuf);
		    }
		  ]])
	      ],
	      [
		ac_cv_func_pcap_findalldevs=yes
	      ],
	      [
		ac_cv_func_pcap_findalldevs=no
	      ])
	  ])
	#
	# Don't check for other new routines that showed up after
	# "pcap_findalldevs()" if we don't have a usable
	# "pcap_findalldevs()", so we don't end up using them if the
	# "pcap.h" is crufty and old and doesn't declare them.
	#
	if test $ac_cv_func_pcap_findalldevs = "yes" ; then
	  AC_DEFINE(HAVE_PCAP_FINDALLDEVS, 1,
	   [Define to 1 if you have the `pcap_findalldevs' function and a pcap.h that declares pcap_if_t.])
	  AC_CHECK_FUNCS(pcap_datalink_val_to_name pcap_datalink_name_to_val)
	  AC_CHECK_FUNCS(pcap_list_datalinks pcap_set_datalink pcap_lib_version)
	  AC_CHECK_FUNCS(pcap_get_selectable_fd)
	fi
	LIBS="$ac_save_LIBS"
])

