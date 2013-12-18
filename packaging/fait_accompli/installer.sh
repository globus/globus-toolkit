#!/bin/sh
packagingdir="$(cd "$(dirname "$(dirname "$0")")" && pwd)"
fait_accompli="$packagingdir/fait_accompli"
#Make sure we built GPT
$packagingdir/build_gpt.pl

VERSION="$(cat "$fait_accompli/version")"
MAJOR="${VERSION%%.*}"
MINOR="${VERSION#*.}"
MINOR="${MINOR%.*}"
INSTALLER=$packagingdir/gt$VERSION-all-source-installer
GPT=$packagingdir/gpt*.tar.gz

PACKAGES=myproxy

echo Making configure/make installer

avoid_bootstrap=0
while getopts "f:a" arg; do
    case "$arg" in
        f)
            flavor="$OPTARG"
            ;;
        a)
            avoid_bootstrap=-a
            ;;
    esac
done

echo "Step: Creating installer Makefile and bootstrapping."
perl $packagingdir/installer_creation.pl -p $packagingdir/etc/packages ${flavor:+-f "$flavor"} $avoid_bootstrap

if [ $? -ne 0 ]; then
        echo There was trouble making the installer.
        exit 1
fi

echo "Bootstrapping done, about to copy source trees into installer."
echo "This may take a few minutes."

mkdir $INSTALLER
cat $fait_accompli/installer.Makefile.prelude $fait_accompli/makefile_bundle_target.frag $packagingdir/installer_makefile.frag > $INSTALLER/Makefile.in

sed -e "s/@version@/$VERSION/g" \
    -e "s/@major@/$MAJOR/g" \
    -e "s/@minor@/$MINOR/g" \
    $fait_accompli/installer.configure.in > farfleblatt2
autoconf farfleblatt2 > $INSTALLER/configure
chmod +x $INSTALLER/configure
cp $fait_accompli/install-sh $INSTALLER
cp $fait_accompli/config.sub $INSTALLER
cp $fait_accompli/config.guess $INSTALLER
cp $fait_accompli/config.site.in $INSTALLER
sed -e "s/@version@/$VERSION/g" \
    -e "s/@major@/$MAJOR/g" \
    -e "s/@minor@/$MINOR/g" \
    $fait_accompli/installer.INSTALL > $INSTALLER/INSTALL
sed -e "s/@version@/$VERSION/g" \
    -e "s/@major@/$MAJOR/g" \
    -e "s/@minor@/$MINOR/g" \
    $fait_accompli/installer.README > $INSTALLER/README

# untar GPT into the installer dir
tar -C $INSTALLER -xzf $GPT
# installer wants gpt to not be in a versioned directory
mv $INSTALLER/gpt-* $INSTALLER/gpt

# copy quickstart into the installer dir
cp -RpL $packagingdir/quickstart $INSTALLER

# Symlink over the bootstrapped CVS dirs.
# Must use -h in tar command to dereference them
mkdir $INSTALLER/source-trees
CPOPTS=RpL

cp -${CPOPTS} $packagingdir/source-trees/* $INSTALLER/source-trees
#rm -fr $INSTALLER/source-trees/autotools

echo Done creating installer.
