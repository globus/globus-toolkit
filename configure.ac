#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([gridftp-hdfs], [0.1.0], [osg-hadoop@opensciencegrid.org])

AM_INIT_AUTOMAKE([gridftp-hdfs], [0.1.0])

AC_CONFIG_SRCDIR([src/globus_gridftp_server_hdfs.c])
#AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

AC_ARG_WITH(logdir, [  -with-logdir=LOG        Log directory location], [logdir=${withval}], [logdir=/var/log])

AS_IF([ test "x${JAVA_HOME}" != x ], , [JAVA_HOME=/usr/java/latest])

AC_ARG_WITH(java, [  --with-java=JAVA_HOME   Location of java], [JAVA_HOME=${withval}])
AS_IF([ test -e ${JAVA_HOME}/include ], [JNIHDIR=${JAVA_HOME}/include], )
AC_CHECK_FILE(${JNIHDIR}/jni.h, ,[AC_MSG_ERROR(Can't find jni.h in ${JNIHDIR})])

AS_IF([ test -e ${JAVA_HOME}/jre/lib/amd64 ], LDFLAGS=["$LDFLAGS -L${JAVA_HOME}/jre/lib/amd64 -L${JAVA_HOME}/jre/lib/amd64/server"])
AS_IF([ test -e ${JAVA_HOME}/jre/lib/i386 ], LDFLAGS=["$LDFLAGS -L${JAVA_HOME}/jre/lib/i386 -L${JAVA_HOME}/jre/lib/i386/server"])

AC_ARG_WITH(hadoop, [  --with-hadoop=HADOOP_HOME Location of $HADOOP_HOME], [HADOOPHOME=${withval}], [HADOOPHOME=$HADOOP_HOME])
AC_CHECK_FILE(${HADOOPHOME}/src/c++/libhdfs/hdfs.h, INCLUDE=["$INCLUDE -I${HADOOPHOME}/src/c++/libhdfs"],)
AC_CHECK_FILE(${HADOOPHOME}/build/libhdfs/libhdfs.so, LDFLAGS=["$LDFLAGS -L${HADOOPHOME}/build/libhdfs"],)

AC_ARG_WITH(globus, [  --with-globus=GLOBUS_LOCATION Location of globus], [GLOBUSHOME=${withval}], [GLOBUSLOCATION=$GLOBUS_LOCATION])
AC_CHECK_FILE(${GLOBUSLOCATION}, ,[GLOBUSLOCATION=/opt/globus])
AC_CHECK_FILE(${GLOBUSLOCATION}/include/gcc64, INCLUDE=["$INCLUDE -I${GLOBUSLOCATION}/include/gcc64"])
AC_CHECK_FILE(${GLOBUSLOCATION}/include/gcc32, INCLUDE=["$INCLUDE -I${GLOBUSLOCATION}/include/gcc32"])

# Checks for libraries.
AC_CHECK_LIB([hdfs], [hdfsRead], , [AC_MSG_ERROR(Could not find libhdfs)], [-ljvm])

# Checks for header files.
AC_CHECK_HEADERS([unistd.h], ,[AC_MSG_ERROR(Could not find unistd.h header)])
#AC_CHECK_HEADERS([hdfs.h], ,[AC_MSG_ERROR(Could not find hdfs.h header)])
#AC_CHECK_HEADERS([globus_gridftp_server.h], ,[AC_MSG_ERROR(Could not find globus_gridftp_server.h header)])

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

if test "x${prefix}" == "xNONE" ; then
    prefix_resolved=${ac_default_prefix}
else
    eval "prefix_resolved=\"${prefix}\""
fi

if test "x${exec_prefix}" == "xNONE" ; then
    exec_prefix_resolved=${ac_default_prefix}
else
    eval "exec_prefix_resolved=\"${exec_prefix}\""
fi

if test "x${sysconfdir}" == "xNONE/etc" ; then
    sysconfdir_resolved=${ac_default_prefix}
else
    eval "sysconfdir_resolved=\"${sysconfdir}\""
fi

AC_SUBST(HADOOPHOME)
AC_SUBST(JNIHDIR)
AC_SUBST(INCLUDE)
AC_SUBST(GLOBUSLOCATION)
AC_SUBST(logdir)
AC_SUBST(exec_prefix_resolved)
AC_SUBST(prefix_resolved)
AC_SUBST(sysconfdir_resolved)

AC_CONFIG_FILES([Makefile src/Makefile conf/Makefile scripts/Makefile conf/gridftp-inetd.conf conf/gridftp-hdfs scripts/gridftp-hdfs-inetd scripts/gridftp-hdfs-standalone])
AC_OUTPUT

