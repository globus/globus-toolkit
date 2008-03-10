#! /bin/sh

topdir=`pwd`

tar zxf gsoap_2.7.9i.tar.gz

# build and install gsoap
if pkg-config openssl 2> /dev/null; then
    CPPFLAGS="`pkg-config --cflags openssl`"
    LDFLAGS="`pkg-config --libs openssl`"
    export CPPFLAGS
    export LDFLAGS
fi

(cd gsoap-2.7
./configure --prefix=$topdir/INSTALL
make
make install
)

tar zxf xacml-1.0.tar.gz
(cd xacml-1.0
./configure   --prefix=$topdir/INSTALL \
              --with-gsoap=$topdir/INSTALL
make all install
)

tar zxf xacml_test-1.0.tar.gz
(cd xacml_test-1.0
./configure  --prefix=$topdir/INSTALL
make all install
)
