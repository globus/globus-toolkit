#!/bin/sh

TAG2=globus_2_4_3_pre1
TAG3=globus_3_0_branch

if [ x$GLOBUS_LOCATION = x ]; then
	echo "If you set a GLOBUS_LOCATION, I will install there."
fi
export GPT_LOCATION=`pwd`/gpt-2.2.9

./make-packages.pl -t2=$TAG2 -t3=$TAG3 --uncool --version=3.0.2pre --paranoia $@

if [ $? -ne 0 ]; then
	echo Packaging failed.
	exit
fi

mkdir installer
cp bundle-output/*.tar.gz installer
mkdir installer/schedulers
cd installer/schedulers
tar xzf ../schedulers*.tar.gz

rm globus_core*
rm packaging_list
rm ../schedulers*.tar.gz

if [ x$GLOBUS_LOCATION != x ]; then
	cd ..
	$GPT_LOCATION/sbin/gpt-build globus-reso*server* gcc32dbg
	$GPT_LOCATION/sbin/gpt-build globus-data*server* gcc32dbg
	# $GPT_LOCATION/sbin/gpt-build globus-info* gcc32dbgpthr
	$GPT_LOCATION/sbin/gpt-build gt3-all-src* gcc32dbg
	$GPT_LOCATION/sbin/gpt-build ogsi-cbindings* gcc32dbg
	$GPT_LOCATION/sbin/gpt-build gt3-extras* gcc32dbg
	$GPT_LOCATION/sbin/gpt-build mmjfs-3* gcc32dbg
	$GPT_LOCATION/sbin/gpt-build -static mmjfs-s* gcc32dbg

	$GPT_LOCATION/sbin/gpt-postinstall
fi
