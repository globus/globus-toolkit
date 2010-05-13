#!/bin/sh

VERSION=`cat fait_accompli/version`
INSTALLER=gt$VERSION-all-source-installer
AUTOTOOLS=source-trees/autotools/autoconf-2.59/config
GPT=gpt*.tar.gz
TARFILES=netlogger-c-4.0.2.tar.gz
CVSROOT=cvs.globus.org:/home/globdev/CVS/globus-packages

#GT5 bundles
BUNDLES=globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-xio-extra-drivers,globus-rls-server,prews-test,globus-gsi,gsi_openssh_bundle,globus-gsi-test,gram5-condor,gram5-lsf,gram5-pbs,cas_callout

PACKAGES=globus_rls_client_jni,myproxy,globus_openssl_backup

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

if [ "X$BRANCH" != "X" ]; then
    echo Step: Updating source with branch $BRANCH.
    mkdir tmp-branch
    cd tmp-branch
    cvs -Q co -r $BRANCH all
    cd ..
    cp -R tmp-branch/* source-trees/
    rm -rf tmp-branch
    INSTALLER=gt$BRANCH-all-source-installer
fi

if [ -d scripts ]; then
   echo
   echo "Step: Running Scripts..."
   for SCRIPT in `ls scripts 2>/dev/null`; do
       echo "Running $SCRIPT"
       scripts/$SCRIPT 
       if [ $? -ne 0 ]; then
           echo There was trouble running scripts/$SCRIPT
           exit 16
       fi
   done
   echo
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

sed -e "s/@version@/$VERSION/g" fait_accompli/installer.configure.in > farfleblatt
source-trees/autotools/bin/autoconf farfleblatt > $INSTALLER/configure
chmod +x $INSTALLER/configure
cp $AUTOTOOLS/install-sh $INSTALLER
cp $AUTOTOOLS/config.sub $INSTALLER
cp $AUTOTOOLS/config.guess $INSTALLER
sed -e "s/@version@/$VERSION/g" fait_accompli/installer.INSTALL > $INSTALLER/INSTALL
sed -e "s/@version@/$VERSION/g" fait_accompli/installer.README > $INSTALLER/README

# untar GPT into the installer dir
tar -C $INSTALLER -xzf $GPT

# copy quickstart into the installer dir
cp -r quickstart $INSTALLER

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
rm -fr $INSTALLER/source-trees/autotools

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
   tar -C $INSTALLER/source-trees-thr -xzf fait_accompli/$f
done

echo Done creating installer.
