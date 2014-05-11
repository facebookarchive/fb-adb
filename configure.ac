AC_INIT([adbx], [1.0], [dancol@dancol.org])
if test "$srcdir" = "."; then
   dnl We configure this directory multiple times, once for each stub
   dnl architecture, but we can only do that if we're out of tree for
   dnl _all_ builds, unfortunately, including the one for the normal
   dnl host system.
   AC_MSG_ERROR([Only out-of-tree builds supported.  Try mkdir build && cd build && ../configure.])
fi
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_PROG_CC_C99
AM_PROG_AS
AC_PROG_SED
AC_CHECK_FUNCS([ppoll dup3 mkostemp pselect])

CPPFLAGS="$CPPFLAGS -Wall -Werror -D_GNU_SOURCE=1"

dnl _FORTIFY_SOURCE produces too many false positives: read(fd, buf,
dnl min(sizeof(buf), x)), unsigned x, tricks _FORTIFY_SOURCE into
dnl thinking we might overflow the buffer, but we clearly can't.
CPPFLAGS="$CPPFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"

AC_ARG_WITH([android-ndk],
            AS_HELP_STRING([--with-android-ndk=NDK],
            [Android NDK location]))
if test -z "$with_android_ndk"; then
   AC_MSG_ERROR([Android NDK location not given])
fi
andk=$with_android_ndk
if ! test -f "$andk/build/tools/make-standalone-toolchain.sh"; then
   AC_MSG_ERROR([Android NDK not in "$andk"])
fi

if test -z "$BUILD_STUB"; then
   STUB_SUBDIRS="stub-x86 stub-arm"
   STUB_BINARIES="stub-x86/adbx stub-arm/adbx"
   AC_CONFIG_SUBDIRS([stub-x86 stub-arm])
   AC_SUBST([STUB_BINARIES])
else
   CPPFLAGS="$CPPFLAGS -DBUILD_STUB=1"
   CFLAGS="$CFLAGS -Wno-format"
fi

AC_ARG_ENABLE([checking],
        AS_HELP_STRING([--enable-checking],
        [Enable assertions (default no)]),
        [],
        [enable_checking=no])
if test "$enable_checking" = "yes"; then
   true
elif test "$enable_checking" = "no"; then
   CPPFLAGS="$CPPFLAGS -DNDEBUG=1"
else
   AC_MSG_ERROR([invalid value for --enable-checking: need yes or no])
fi

AM_CONDITIONAL([BUILD_STUB], [test -n "$BUILD_STUB"])
AC_SUBST([STUB_SUBDIRS])
AC_CONFIG_FILES([Makefile])
echo "Checking enabled?    ${enable_checking}"
AC_OUTPUT
