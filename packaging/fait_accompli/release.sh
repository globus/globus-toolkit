#!/bin/sh

VERSION="3.2alpha"
INSTALLER="gt${VERSION}-base-installer"
GPT="fait_accompli/gpt-3.0.1-src.tar.gz"

mkdir $INSTALLER

./make-packages.pl --bundles=gt3-all-src,globus-data-management-server,globus-resource-management-server,ogsi-cbindings,gt3-extras --version=$VERSION --installer=install-gt3
./make-packages.pl -n --bundles=mmjfs,mmjfs-static,scheduler-fork --installer=install-gt3-mmjfs --version=$VERSION

cp bundle-output/*.tar.gz $INSTALLER
cp bundle-output/install-gt3* $INSTALLER
cp $GPT $INSTALLER

rm -fr *-output

./make-packages.pl -n --bundles=scheduler-pbs,scheduler-condor,scheduler-lsf --version=gt3.2alpha

mkdir  $INSTALLER/schedulers
cp bundle-output/*.tar.gz  $INSTALLER/schedulers

./make-packages.pl -n --packages=globus_gram_reporter,globus_gram_reporter_setup_pbs,globus_gram_reporter_setup_lsf,globus_gram_reporter_setup_condor --version=gt3.2alpha

mkdir  $INSTALLER/schedulers/gram-reporters
cp package-output/globus_gram_reporter*.tar.gz  $INSTALLER/schedulers/gram-reporters
