#!/bin/sh

TAG2=HEAD
TAG3=HEAD

INSTALL_BUNDLES=globus-resource-management-server,gt3-all-src,mmjfs,mmjfs-static,scheduler-fork,ogsi-cbindings,gt3-extras
BUILD_BUNDLES=ogsi-cbindings,scheduler-pbs,scheduler-condor,scheduler-lsf

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
