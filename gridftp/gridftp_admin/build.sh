#! /bin/sh

flavor=$1
start_dir=`pwd`
rm -rf service_bindings client_bindings

cd WSDL/
./preprocess-wsdl
cd $start_dir

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$GLOBUS_LOCATION/lib/globus_service_modules/wsrf/services

rm -f `find $GLOBUS_LOCATION -name 'libGridFTPAdminService*'`

$GLOBUS_LOCATION/bin/globus-wsrf-cgen -no-client -d $PWD/service_bindings -s gridftp_admin_service $GLOBUS_LOCATION/share/schema/gridftp/gridftp_admin_service.wsdl
$GLOBUS_LOCATION/bin/globus-wsrf-cgen -no-service -d $PWD/client_bindings -s gridftp_admin_client $GLOBUS_LOCATION/share/schema/gridftp/gridftp_admin_service.wsdl

cp -f $start_dir/service_Makefile.am service_bindings/GridFTPAdminService/Makefile.am
#cp -f $start_dir/resource_setup.c admin_bindings/GridFTPAdminService
cp -f $start_dir/service_pkg_data_src.gpt.in service_bindings/pkgdata/pkg_data_src.gpt.in
cp -f $start_dir/service_configure.in service_bindings/configure.in


cd client_bindings
./bootstrap
./configure --with-flavor=$flavor
make
make install

cd $start_dir
cd service_bindings
./bootstrap
./configure --with-flavor=$flavor
make
make install

cd $start_dir
cd client_source
./bootstrap
./configure --with-flavor=$flavor
make
make install

