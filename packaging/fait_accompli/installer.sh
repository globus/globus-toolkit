#!/bin/sh

VERSION=TRUNK
INSTALLER=gt$VERSION-all-source-installer
AUTOTOOLS=source-trees/autotools/autoconf-2.59/config
GPT=gpt*.tar.gz

BUNDLES=globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-rls-server,gt4-java-ws-core,gt4-java-admin,gt4-mds,gt4-delegation,gt4-rft,gt4-gram,gt4-gram-pbs,gt4-gram-condor,gt4-gram-lsf,gt4-cas,gt4-c-ws-core,prews-test,globus-internationalization,gt4-java-ws-core-test,gt4-c-ws-core-test,gt4-mds-test,gt4-gram-test,gt4-cas-delegation-test,gt4-rft-test,gt4-webmds,gt4-webmds-test,globus-gsi,gt4-replicator,gt4-wsrls,gsi_openssh_bundle,gridshib_bundle
PACKAGES=globus_rendezvous,globus_xio_udt_ref_driver,globus_xio_skeleton_driver,globus_rls_client_java,myproxy,gridway


echo Making configure/make installer
echo Step: Checking out and building autotools.
./make-packages.pl --trees=autotools --skippackage --skipbundle $@
if [ $? -ne 0 ]; then
	echo There was trouble building autotools
	exit 2
fi

echo Step: Checking out source code.
./make-packages.pl --trees=gt --bundles=$BUNDLES --packages=$PACKAGES --skippackage --skipbundle --deps $@
if [ $? -ne 0 ]; then
	echo There was trouble checking out sources
	exit 8
fi

if [ -d patches ]; then
   echo
   echo "Step: Patching..."
   for PATCH in `ls patches 2>/dev/null`; do
       echo "Applying $PATCH"
       cat patches/$PATCH | patch -p0
       if [ $? -ne 0 ]; then
           echo There was trouble applying patches/$PATCH
           exit 16
       fi
   done
   echo
fi

echo "Step: Creating installer Makefile and bootstrapping."
./make-packages.pl --trees=gt --bundles=$BUNDLES --packages=$PACKAGES -n --list-packages --deps --deporder $@ --installer=farfleblatt

if [ $? -ne 0 ]; then
	echo There was trouble making the installer.
	exit 1
fi

echo Bootstrapping done, about to copy source trees into installer.
echo This may take a few minutes.

mkdir $INSTALLER
cat fait_accompli/installer.Makefile.prelude farfleblatt > $INSTALLER/Makefile.in
rm farfleblatt

source-trees/autotools/bin/autoconf fait_accompli/installer.configure.in > $INSTALLER/configure
chmod +x $INSTALLER/configure
cp $AUTOTOOLS/install-sh $INSTALLER
cp $AUTOTOOLS/config.sub $INSTALLER
cp $AUTOTOOLS/config.guess $INSTALLER
cp fait_accompli/installer.INSTALL $INSTALLER/INSTALL
cp fait_accompli/installer.README $INSTALLER/README

# untar GPT into the installer dir
tar -C $INSTALLER -xzf $GPT

# Symlink over the bootstrapped CVS dirs.
# Must use -h in tar command to dereference them
mkdir $INSTALLER/source-trees
cp --version > /dev/null 2>&1;
if [ $? -eq 0 ]; then
   CPOPTS=RpL
else
   CPOPTS=Rp
fi


cp -${CPOPTS} source-trees/* $INSTALLER/source-trees

HAVE_LNDIR=0
lndir > /dev/null 2>&1;
if [ $? -eq 1 ]; then
    HAVE_LNDIR=1
fi

if [ "X$HAVE_LNDIR" = "X1" ]; then
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

echo Done creating installer.
