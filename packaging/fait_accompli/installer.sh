#!/bin/sh

VERSION=3.9.5
INSTALLER=gt$VERSION-all-source-installer
AUTOTOOLS=source-trees/autotools/autotools/autoconf-2.59/config
GPT=gpt-3.2autotools2004-src.tar.gz

echo Making configure/make installer
./make-packages.pl --trees=autotools --skippackage --skipbundle $@
./make-packages.pl --bundles=globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-information-services-server,globus-information-services-client,globus-information-services-sdk,globus-rls-server,gt4-java-ws-core,gt4-mds,gt4-delegation,gt4-rft,gt4-gram,gt4-gram-pbs,gt4-gram-condor,gt4-gram-lsf,gt4-cas,gt4-c-ws-core,prews-test,globus-internationalization,gt4-java-ws-core-test,gt4-c-ws-core-test,gt4-mds-test,gt4-gram-test,gt4-cas-delegation-test,gt4-rft-test,gt4-webmds,globus-gsi,gt4-replicator --list-packages --deps --deporder $@ | tee farfleblatt

if [ $? -ne 0 ]; then
	echo There was trouble making the installer.
	exit 1
fi

mkdir $INSTALLER
sed -e '1,/Final package build list/d' farfleblatt > farfle2
cat fait_accompli/installer.Makefile.prelude farfle2 > $INSTALLER/Makefile.in
rm farfleblatt farfle2

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
for f in `pwd`/source-trees/gt2-cvs/*; do
   g=$INSTALLER/source-trees/`basename $f`
   mkdir $g;
   lndir -silent $f $g;
done
for f in `pwd`/source-trees/wsrf-cvs/*; do
   g=$INSTALLER/source-trees/`basename $f`
   mkdir $g;
   lndir -silent $f $g;
done
