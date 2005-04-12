#! /bin/sh

if [ "X$1" = "X" ]; then
    echo "generate-stubs <dsi name> <flavor>"
    exit 1
fi

if [ "X$2" = "X" ]; then
    echo "generate-stubs <dsi name> <flavor>"
    exit 1
fi

if [ "X$GLOBUS_LOCATION" = "X" ]; then
    echo "$GLOBUS_LOCATION must be defined"
    exit 1
fi

name=$1
flavor=$2

date=`date +%s`

$GLOBUS_LOCATION/bin/globus-makefile-header -flavor=$flavor globus_gridftp_server > makefile_header

sed -e "s/@DSI@/$name/g" -e "s/@DATE@/$date/g" globus_gridftp_server_dsi.c.in > globus_gridftp_server_$name.c
sed -e "s/@DSI@/$name/g" -e "s/@FLAVOR@/$flavor/g" Makefile.in > Makefile
