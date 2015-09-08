dnl Copyright (c) 2014, Facebook, Inc.
dnl All rights reserved.
dnl
dnl This source code is licensed under the BSD-style license found in
dnl the LICENSE file in the root directory of this source tree. An
dnl  additional grant of patent rights can be found in the PATENTS file
dnl in the same directory.
dnl

AC_INIT([fb-adb], [1.5.99-3], [dancol@fb.com])
if test "$srcdir" = "."; then
   dnl We configure this directory multiple times, once for each stub
   dnl architecture, but we can only do that if we're out of tree for
   dnl _all_ builds, unfortunately, including the one for the normal
   dnl host system.
   AC_MSG_ERROR([Only out-of-tree builds supported.  Try mkdir build && cd build && ../configure.])
fi
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

platform=
AC_ARG_WITH([android-ndk],
            AS_HELP_STRING([--with-android-ndk=NDK],
            [Android NDK location (defaults to $ANDROID_NDK)
             "system" means to try finding cross-compilers
             in PATH instead of in an NDK.]))
if test -z "$with_android_ndk" && test -n "$ANDROID_NDK"; then
   with_android_ndk=$ANDROID_NDK
fi
if test -z "$with_android_ndk"; then
   AC_MSG_ERROR([Android NDK location not given])
fi
andk=$with_android_ndk
if test "$andk" = "system"; then
  echo "Using system Android cross-compilers"
  platform=system
else
  if ! test -f "$andk/build/tools/make-standalone-toolchain.sh"; then
     AC_MSG_ERROR([Android NDK not in "$andk"])
  fi
  echo "Using Android NDK at $andk"
fi

dnl We default to android-19 because it's broadly compatible
AC_ARG_WITH([android-platform],
            AS_HELP_STRING([--with-android-platform=API-VERSION],
            [Android NDK API version (default android-19).
             "latest" means to use latest from the NDK.]))

if test "$platform" = "system"; then
  if test -n "$with_android_platform"; then
    AC_MSG_ERROR([Cannot specify platform when using system cross-compilers])
  fi
else
  if test -z "$with_android_platform"; then
    platform=android-19
  elif test "$with_android_platform" = "latest"; then
    platform=$(ls -1 "$andk"/platforms | sort -rk2 -t- -n | head -1)
  else
    platform=$with_android_platform
  fi
fi

if test "$platform" = "system"; then
  true
else
  if test -n "$BUILD_STUB"; then
     rm -rf toolchain
     mkdir -p toolchain
     if test $host_cpu = i686; then
        toolchain_cpu=x86
      else
        toolchain_cpu=arm
      fi
     echo "Configuring native NDK toolchain for $platform/$toolchain_cpu"

     "$andk"/build/tools/make-standalone-toolchain.sh \
       --install-dir=toolchain --platform=$platform \
       --arch=$toolchain_cpu
     export PATH="$PWD/toolchain/bin:$PATH"
  fi
fi

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_SUBST([PATH])

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_SYS_LARGEFILE
AC_CHECK_SIZEOF([off_t])

AC_PROG_SED
AC_CHECK_TOOLS(RANLIB, [gcc-ranlib ranlib])
AC_CHECK_TOOLS(AR, [gcc-ar ar])
AC_CHECK_TOOLS(STRIP, [strip])
AM_PROG_AR

AC_CHECK_PROGS(PYTHON3, [python3], [
  AC_MSG_ERROR([python3 required for building])
])

AC_CHECK_PROGS(POD2MAN, [pod2man], [
  AC_MSG_ERROR([pod2man required for man page generation])
])

if test -z "$BUILD_STUB"; then
  AC_PATH_PROG([XXD], [xxd])
  if test -z "$XXD"; then
    AC_MSG_ERROR([xxd is required to build])
  fi

  if test -n "$HOST_CFLAGS"; then
     CFLAGS="$CFLAGS $HOST_CFLAGS"
  fi

  if test -n "$HOST_LDFLAGS"; then
     CFLAGS="$CFLAGS $HOST_LDFLAGS"
  fi
fi

if test -n "$BUILD_STUB"; then
  if test -n "$STUB_CFLAGS"; then
     CFLAGS="$CFLAGS $STUB_CFLAGS"
  fi

  if test -n "$STUB_LDFLAGS"; then
     CFLAGS="$CFLAGS $STUB_LDFLAGS"
  fi
fi


AC_CHECK_FUNCS([ppoll signalfd4 dup3 mkostemp kqueue pipe2 ptsname])
AC_CHECK_FUNCS([accept4 fopencookie funopen clock_gettime execvpe])
AC_CHECK_FUNCS([fallocate futimes posix_fallocate ftruncate64])
AC_CHECK_FUNCS([posix_fadvise])

is_android=$(echo "$CC" | grep android)
if test -n "$BUILD_STUB" && test -z "$is_android" ; then
   AC_MSG_ERROR([could not find Android cross-compiler for $host])
fi

CPPFLAGS="$CPPFLAGS -Wall"

dnl _FORTIFY_SOURCE produces too many false positives: read(fd, buf,
dnl min(sizeof(buf), x)), unsigned x, tricks _FORTIFY_SOURCE into
dnl thinking we might overflow the buffer, but we clearly can't.
CPPFLAGS="$CPPFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"

dnl Each of these stub variants has a corresponding source
dnl subdirectory; each subdirectory contains a dummy configure script
dnl that re-invokes this script with BUILD_STUB on the command line.
dnl To add a new stub variant, add a new entry to this list, new
dnl subdirectories, and new entries in stubs.s.

m4_define([xxstubs], [stub-x86, stub-arm, stub-x86-pic, stub-arm-pic])

if test -z "$BUILD_STUB"; then
  STUB_BINARIES=
  STUB_SUBDIRS=
  m4_foreach([xxstub], [xxstubs], [
    AC_CONFIG_SUBDIRS(xxstub)
    STUB_BINARIES="$STUB_BINARIES xxstub/stub"
    STUB_SUBDIRS="$STUB_SUBDIRS xxstub"
  ])
  AC_SUBST([STUB_BINARIES])
fi

AC_ARG_ENABLE([checking],
        AS_HELP_STRING([--enable-checking],
        [Enable assertions (default no)]),
        [true],
        [enable_checking=no])
if test "$enable_checking" = "yes"; then
  CPPFLAGS="$CPPFLAGS -Werror"
elif test "$enable_checking" = "no"; then
  CPPFLAGS="$CPPFLAGS -DNDEBUG=1"
else
  AC_MSG_ERROR([invalid value for --enable-checking: need yes or no])
fi

AC_ARG_ENABLE([input-output-termios],
        AS_HELP_STRING([--enable-input-output-termios],
        [Enable separate input and output terminal configuration]),
        [true],
        [enable_input_output_termios=no])
if test "$enable_input_output_termios" = "yes"; then
  AC_DEFINE([INPUT_OUTPUT_TERMIOS], [1])
elif test "$enable_input_output_termios" = "no"; then
  true
else
  AC_MSG_ERROR([invalid value for --enable-input-output-termios: need yes or no])
fi

AC_MSG_CHECKING([ncurses])
old_LIBS=$LIBS
LIBS="$LIBS -lncurses"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([
#include <curses.h>
#include <term.h>
], [setupterm((char*)0,0,NULL);])],
  [AC_MSG_RESULT([yes])
   AC_DEFINE([USE_NCURSES])
   ncurses=yes
   ],
  [AC_MSG_RESULT([no])
   LIBS=$old_LIBS
   ncurses=no])

AC_ARG_ENABLE([git-stamp],
        AS_HELP_STRING(
          [--enable-git-stamp],
          [include the git revision in the version output]),
        [true],
        [enable_git_stamp=no])

if test "$enable_git_stamp" = "yes"; then
  AC_DEFINE([HAVE_GIT_STAMP], [1])
fi

AC_ARG_ENABLE([debuggable-stubs],
        AS_HELP_STRING(
          [--enable-debuggable-stubs],
          [allow stubs to be debuggable; causes build to be]
          [non-deterministic]),
        [true],
        [enable_debuggable_stubs=no])
AM_CONDITIONAL([STRIP_STUBS], [test "$enable_debuggable_stubs" = "no"])

AC_CHECK_MEMBERS([struct stat.st_mtim])
AC_CHECK_MEMBERS([struct stat.st_ctim])
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_blocks])
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct dirent.d_type], [], [], [
#include <dirent.h>
])

AM_CONDITIONAL([GIT_STAMP], [test "$enable_git_stamp" = "yes"])
AM_CONDITIONAL([BUILD_STUB], [test -n "$BUILD_STUB"])
AM_CONDITIONAL([BUILD_PIC], [test -n "$BUILD_PIC"])
AC_SUBST([STUB_SUBDIRS])
AC_CONFIG_FILES([Makefile])
echo "Debuggable stubs?      ${enable_debuggable_stubs}"
echo "Checking enabled?      ${enable_checking}"
echo "Git stamp included?    ${enable_git_stamp}"
echo "Input-output termios?  ${enable_input_output_termios}"
echo "Using ncurses?         ${ncurses}"

if test "$enable_debuggable_stubs" != "no"; then
  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65015
  AC_MSG_WARN([allowing debug information stubs; build non-deterministic])
fi

AC_OUTPUT
