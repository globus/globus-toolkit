#
# Configuration file for using the XML library in GNOME applications
#
prefix="$(GLOBUS_LOCATION)"
exec_prefix="$(GLOBUS_LOCATION)"
libdir="${exec_prefix}/lib"
includedir="${prefix}/include"

XMLSEC_LIBDIR="${exec_prefix}/lib"
XMLSEC_INCLUDEDIR=" -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XSLT=1 -DXMLSEC_NO_XKMS=1 -I${prefix}/include/xmlsec1     -DXMLSEC_CRYPTO_OPENSSL=1  -DXMLSEC_OPENSSL_096=1 -DXMLSEC_CRYPTO=\\\"openssl\\\""
XMLSEC_LIBS="-L${exec_prefix}/lib -lxmlsec1-openssl -lxmlsec1  -ldl    -lcrypto"
MODULE_VERSION="xmlsec-1.2-openssl"

