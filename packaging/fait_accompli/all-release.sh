#!/bin/sh

VERSION="3.3.0"
TAGOPTS="-t2=HEAD -t3=HEAD"
INSTALLER="gt${VERSION}-all-source-installer"
GPT="fait_accompli/gpt-3.0.1-src.tar.gz"

mkdir $INSTALLER

./make-packages.pl $TAGOPTS --bundles=gt3-all-src,gt2-unthreaded,gt2-threaded,ogsi-cbindings,gt3-extras,globus-rls-server --version=$VERSION --installer=install-gt3 $@

if [ $? -ne 0 ]; then
	echo "An error occurred."
	exit
fi

./make-packages.pl -n --bundles=mmjfs,mmjfs-static,scheduler-fork --installer=install-gt3-mmjfs --version=$VERSION

if [ $? -ne 0 ]; then
	echo "An error occurred."
	exit
fi

mkdir $INSTALLER/bundles
cp bundle-output/*.tar.gz $INSTALLER/bundles
cp bundle-output/install-gt3* $INSTALLER
chmod +x $INSTALLER/install-gt3 $INSTALLER/install-gt3-mmjfs
cp $GPT $INSTALLER

rm -fr *-output

./make-packages.pl -n --bundles=scheduler-pbs,scheduler-condor,scheduler-lsf --version=$VERSION
if [ $? -ne 0 ]; then
	echo "An error occurred."
	exit
fi


mkdir  $INSTALLER/schedulers
cp bundle-output/*.tar.gz  $INSTALLER/schedulers

./make-packages.pl -n --packages=globus_gram_reporter,globus_gram_reporter_setup_pbs,globus_gram_reporter_setup_lsf,globus_gram_reporter_setup_condor --version=$VERSION
if [ $? -ne 0 ]; then
	echo "An error occurred."
	exit
fi


mkdir  $INSTALLER/schedulers/gram-reporters
cp package-output/globus_gram_reporter*.tar.gz  $INSTALLER/schedulers/gram-reporters

if [ -d contrib ]; then
    cp -Rp contrib $INSTALLER
fi

