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
AM_CONDITIONAL([BUILD_STUB], [test -n "$BUILD_STUB"])
AC_SUBST([STUB_SUBDIRS])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
