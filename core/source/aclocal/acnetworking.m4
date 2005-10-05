

AC_DEFUN([CHECK_NEED_LSOCKET], [

dnl
dnl Check whether we need -lsocket
dnl

AC_MSG_CHECKING(for -lsocket)

if test "${lac_cv_lsocket+set}" = set; then
    AC_MSG_RESULT([(cached) $lac_cv_lsocket])
else
    AC_TRY_LINK(
        [
            #include <sys/types.h>
            #include <sys/socket.h>
        ],
        [
            int fd;
            fd = socket(AF_INET,SOCK_STREAM,0);
        ],
        [
            lac_cv_lsocket="no"	
        ],
        [
            lac_cv_lsocket="yes"
            EXTERNAL_LIBS="$EXTERNAL_LIBS -lsocket"
        ]
    )

    AC_MSG_RESULT($lac_cv_lsocket)
fi

])


AC_DEFUN([CHECK_NEED_LNSL], [

dnl
dnl Check whether we need -lnsl
dnl

AC_MSG_CHECKING(for -lnsl)

if test "${lac_cv_lnsl+set}" = set; then
    AC_MSG_RESULT([(cached) $lac_cv_lnsl])
else

    AC_TRY_LINK(
        [
            #include <netdb.h>
        ],
        [
            struct hostent * host;
            host = gethostbyname("localhost");
        ],
        [
            lac_cv_lnsl="no"	
        ],
        [
            lac_cv_lnsl="yes"
            EXTERNAL_LIBS="$EXTERNAL_LIBS -lnsl"
        ]
    )

    AC_MSG_RESULT($lac_cv_lnsl)
fi
])



