#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([puny-ws], [0.0.1], [m@ahungry.com])

AC_LANG([C])

# Checks for programs.

# Checks for libraries.
AC_CHECK_LIB([curl], [curl_easy_init], [], [AC_MSG_ERROR([Couldn't find libcurl.])])
AC_CHECK_LIB([websockets], [lws_service], [], [AC_MSG_ERROR([Couldn't find libwebsockets.])])

# Checks for header files.
AC_CHECK_HEADER(libwebsockets.h, [], [AC_MSG_ERROR([Couldn't find libwebsockets.h])])
AC_CHECK_HEADER(curl/curl.h, [], [AC_MSG_ERROR([Couldn't find curl/curl.h])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
