#!/bin/sh

TAG2=HEAD
TAG3=HEAD

INSTALL_BUNDLES=gt2-unthreaded,globus-resource-management-server,globus-data-management-server,globus-data-management-client,gt4-java-ws-core,gt4-delegation,gt4-rft,gt4-gram
BUILD_BUNDLES=gt4-gram-lsf,gt4-gram-pbs

if [ x$GLOBUS_LOCATION = x ]; then
	echo "If you set a GLOBUS_LOCATION, I will install there."
else
	INSTALL=--install=$GLOBUS_LOCATION
fi
export GPT_LOCATION=`pwd`/gpt-3.0.1

./make-packages.pl -t2=$TAG2 -t3=$TAG3 --bundles="$INSTALL_BUNDLES" $INSTALL $@
if [ $? -ne 0 ]; then
	echo Packaging failed.
	exit
fi

./make-packages.pl -n --bundles="$BUILD_BUNDLES" $@
if [ $? -ne 0 ]; then
	echo Packaging failed.
	exit
fi

if [ x$GLOBUS_LOCATION != x ]; then
	$GPT_LOCATION/sbin/gpt-postinstall
fi
