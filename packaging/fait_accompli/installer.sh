#!/bin/sh

VERSION=4.0.0rc1
INSTALLER=gt$VERSION-all-source-installer
AUTOTOOLS=source-trees/autotools/autotools/autoconf-2.59/config
GPT=gpt-3.2autotools2004-src.tar.gz
# Pre-made tarfiles for gsi-openssh/myproxy
TARFILES="gsi_openssh-3.5-src.tar.gz gsi_openssh_setup-3.5-src.tar.gz myproxy-1.17.tar.gz"

echo Making configure/make installer
./make-packages.pl --trees=autotools,gt2,gt4 --skippackage --skipbundle $@

if [ -d patches ]; then
   echo
   echo "Patching..."
   for PATCH in `ls patches 2>/dev/null`; do
       echo "Applying $PATCH"
       cat patches/$PATCH | patch -p0
   done
   echo
fi

./make-packages.pl --bundles=globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-information-services-server,globus-information-services-client,globus-information-services-sdk,globus-rls-server,gt4-java-ws-core,gt4-java-admin,gt4-mds,gt4-delegation,gt4-rft,gt4-gram,gt4-gram-pbs,gt4-gram-condor,gt4-gram-lsf,gt4-cas,gt4-c-ws-core,prews-test,globus-internationalization,gt4-java-ws-core-test,gt4-c-ws-core-test,gt4-mds-test,gt4-gram-test,gt4-cas-delegation-test,gt4-rft-test,gt4-webmds,gt4-webmds-test,globus-gsi,gt4-replicator --list-packages --deps --deporder -n $@ | tee farfleblatt


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
cp --version > /dev/null 2>&1;
if [ $? -eq 0 ]; then
   CPOPTS=RpL
else
   CPOPTS=Rp
fi

cp -${CPOPTS} source-trees/wsrf-cvs/* $INSTALLER/source-trees
cp -${CPOPTS} source-trees/gt2-cvs/* $INSTALLER/source-trees

which lndir > /dev/null 2>&1;
if [ $? -eq 0 ]; then
   mkdir -p $INSTALLER/source-trees-thr
   if [ $? -ne 0 ]; then
      echo Unable to create $INSTALLER/source-trees-thr
      exit 4
   fi

   cd $INSTALLER/source-trees-thr
   lndir -silent ../source-trees
   rm -fr mds/libtool
   cp -Rp ../source-trees/mds/libtool mds
   rm -fr gsi/simple_ca/setup
   cp -Rp ../source-trees/gsi/simple_ca/setup gsi/simple_ca
   cd ../..
else
   cp -Rp $INSTALLER/source-trees $INSTALLER/source-trees-thr
fi

for f in $TARFILES; do
   tar -C $INSTALLER/source-trees -xzf fait_accompli/$f
done
