#!/bin/sh

TAG2=globus_2_4_3pre2
TAG3=globus_3_0_branch

if [ x$GLOBUS_LOCATION = x ]; then
	echo "If you set a GLOBUS_LOCATION, I will install there."
else
	INSTALL=--install=$GLOBUS_LOCATION
fi
export GPT_LOCATION=`pwd`/gpt-2.2.9

./make-packages.pl -t2=$TAG2 -t3=$TAG3 --uncool --paranoia --bundles="globus-resource-management-server,gt3-all-src,mmjfs,mmjfs-static,ogsi-cbindings,gt3-extras" $INSTALL $@
if [ $? -ne 0 ]; then
	echo Packaging failed.
	exit
fi

./make-packages.pl -n --bundles="schedulers" $@
if [ $? -ne 0 ]; then
	echo Packaging failed.
	exit
fi

if [ x$GLOBUS_LOCATION != x ]; then
	$GPT_LOCATION/sbin/gpt-postinstall
fi
