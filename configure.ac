#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([gridftp_hdfs], [0.1.0], [osg-hadoop@opensciencegrid.org])

AM_INIT_AUTOMAKE([gridftp_hdfs], [0.1.0])

AC_CONFIG_SRCDIR([src/globus_gridftp_server_hdfs.c])
#AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([hdfs], [hdfsRead], , [AC_MSG_ERROR(Could not find libhdfs)])

AC_ARG_WITH(jni, "Location of java", [JNIHDIR=${withval}/include], [JNIHDIR=${JAVA_HOME}/include])
AC_CHECK_FILE(${JNIHDIR}/jni.h, ,[AC_MSG_ERROR(Can't find jni.h in ${JNIHDIR})])

AC_ARG_WITH(hadoop, "Location of $HADOOP_HOME", [HADOOPHDR=${withval}/src/c++/libhdfs], [HADOOPHDR=/usr/include])
AC_CHECK_FILE(${HADOOPHDR}/hdfs.h, ,[AC_MSG_ERROR(Can't find hdfs.h in ${HADOOPHDR})])



# Checks for header files.
AC_CHECK_HEADERS([unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_HEADER_STDC
AC_FUNC_MMAP
AC_FUNC_STRTOD
AC_CHECK_FUNCS([ftruncate gethostname memset munmap strdup strrchr])

AC_SUBST(HADOOPHOME)
AC_SUBST(JNIHDIR)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
