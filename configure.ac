AC_INIT([adbx], [1.0], [dancol@dancol.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC_C99
AC_PROG_SED
AC_CHECK_FUNCS([ppoll dup3 mkostemp])
CPPFLAGS="$CPPFLAGS -Wall -Werror -D_GNU_SOURCE=1"
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
