#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
#AM_INIT_AUTOMAKE(gmcrypto, 1.0)
AM_INIT_AUTOMAKE([no-define subdir-objects foreign])
AC_CONFIG_SRCDIR([gmcrypto.cpp])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH([system-univalue],
  [AS_HELP_STRING([--with-system-univalue],
  [Build with system UniValue (default is no)])],
  [system_univalue=$withval],
  [system_univalue=no])

# Checks for programs.
AC_PROG_CXX

dnl Libtool init checks.
LT_INIT([pic-only])

# Checks for libraries.

dnl univalue check

need_bundled_univalue=yes



if test x$need_bundled_univalue = xyes ; then
  UNIVALUE_CFLAGS='-I$(srcdir)/univalue/include'
  UNIVALUE_LIBS='univalue/libunivalue.la'
fi

AM_CONDITIONAL([EMBEDDED_UNIVALUE],[test x$need_bundled_univalue = xyes])
AC_SUBST(UNIVALUE_CFLAGS)
AC_SUBST(UNIVALUE_LIBS)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

if test x$need_bundled_univalue = xyes; then
  AC_CONFIG_SUBDIRS([src/univalue])
fi

#AC_OUTPUT(Makefile)
AC_CONFIG_FILES([univalue/Makefile Makefile])
AC_OUTPUT

