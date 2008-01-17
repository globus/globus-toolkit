#!/bin/sh

. $GLOBUS_LOCATION/test/globus_test/testcred-env.sh

chmod 0600 ${X509_USER_PROXY}
chmod 0644 ${X509_CERT_DIR}/usercert.pem
chmod 0600 ${X509_CERT_DIR}/userkey.pem

SUBJECT=`grid-proxy-info -identity`;

if [ $? -ne 0 ]; then
   echo Unable to determine identity from proxy file ${X509_USER_PROXY}
   echo Output of command:
   grid-proxy-info -identity
   exit 1
fi

rm -f $GRIDMAP  >/dev/null 2>&1;
grid-mapfile-add-entry -dn "${SUBJECT}" -ln `whoami` -f ${GRIDMAP} \
       >/dev/null 2>&1
if [ $? -ne 0 ]; then
   echo Unable to add identity \"${SUBJECT}\" to gridmap ${GRIDMAP}
   exit 2
fi

rm -f $SECURITY_DESCRIPTOR 2> /dev/null 2>&1;

sed -e "s|@GRIDMAP@|$GRIDMAP|" \
    -e "s|@PROXY@|$X509_USER_PROXY|" \
            < ${SECURITY_DESCRIPTOR}.in \
            > $SECURITY_DESCRIPTOR
