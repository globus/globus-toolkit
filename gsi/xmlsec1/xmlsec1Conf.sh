#
# Configuration file for using the XML library in GNOME applications
#
prefix="/usr"
exec_prefix="${prefix}"
libdir="${exec_prefix}/lib"
includedir="${prefix}/include"

XMLSEC_LIBDIR="${exec_prefix}/lib"
XMLSEC_INCLUDEDIR=" -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -I${prefix}/include/xmlsec1   -I/usr/include/libxml2 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1  -DXMLSEC_CRYPTO=\\\"openssl\\\""
XMLSEC_LIBS="-L${exec_prefix}/lib -lxmlsec1-openssl -lxmlsec1  -ldl  -L/usr/lib -lxml2 -lz -lpthread -lm -L/usr/lib -lxslt -lxml2 -lz -lm -lcrypto"
MODULE_VERSION="xmlsec-1.2.1-openssl"

