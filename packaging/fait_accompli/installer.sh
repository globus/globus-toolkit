#!/bin/sh

VERSION=3.9.4
INSTALLER=gt$VERSION-all-source-installer
AUTOTOOLS=source-trees/autotools/autotools/autoconf-2.59/config
GPT=gpt-3.2autotools2004-src.tar.gz

echo Making configure/make installer
./make-packages.pl --trees=autotools --skippackage --skipbundle $@
./make-packages.pl --bundles=globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-information-services-server,globus-information-services-client,globus-information-services-sdk,globus-rls-server,gt4-java-ws-core,gt4-mds,gt4-delegation,gt4-rft,gt4-gram,gt4-cas,gt4-c-ws-core,prews-test --list-packages --deps --deporder $@ | tee farfleblatt

mkdir $INSTALLER
sed -e '1,/Final package build list/d' farfleblatt > $INSTALLER/Makefile.in
rm farfleblatt

source-trees/autotools/bin/autoconf fait_accompli/installer.configure.in > $INSTALLER/configure
chmod +x $INSTALLER/configure
cp $AUTOTOOLS/install-sh $INSTALLER
cp $AUTOTOOLS/config.sub $INSTALLER
cp $AUTOTOOLS/config.guess $INSTALLER
cp fait_accompli/installer.INSTALL $INSTALLER/INSTALL
cp fait_accompli/installer.README $INSTALLER/README

# untar GPT into the installer dir
tar -C $INSTALLER -xzf fait_accompli/$GPT 

# Symlink over the bootstrapped CVS dirs.
# Must use -h in tar command to dereference them
mkdir $INSTALLER/source-trees
cp -Rpds `pwd`/source-trees/gt2-cvs/* `pwd`/source-trees/wsrf-cvs/* $INSTALLER/source-trees
