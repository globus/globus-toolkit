#!/bin/sh

BASEDIR=$PWD
GT2PKGS="core common xio user_env"
GT3PKGS=chosting

PKGLIST=globus_core,globus_common,globus_common_setup,globus_user_env,globus_axiscpp,globus_expat,globus_axiscpp_wsdl2ws,globus_axiscpp_transport_stdio,globus_axis_server_engine,globus_axis_server_test,globus_service_GetQuoteCPP

if test ! -d $BASEDIR/source-trees; then
	mkdir $BASEDIR/source-trees
fi

if test ! -d $BASEDIR/source-trees/cbindings; then
	mkdir $BASEDIR/source-trees/cbindings
fi

if test ! -d $BASEDIR/source-trees/gt2-cvs; then
	mkdir $BASEDIR/source-trees/gt2-cvs
fi


if test -z "$CVSROOT"; then
	echo ""
	echo "ERROR: Please set CVSROOT to your standard GT2/3 checkout location"
	echo ""
	exit 1
fi


CVSCHECK=`echo $CVSROOT | sed -e "s|.*\(:\).*|\1|"`
if test -z "$CVSCHECK"; then
	CVSBASE=""
else
	CVSBASE=`echo $CVSROOT | sed -e "s|\(.*\):.*|\1|"`
fi

GT2CVS=$CVSBASE:/home/globdev/CVS/globus-packages
GT3CVS=$CVSBASE:/home/globdev/CVS/gridservices

cd $BASEDIR/source-trees/gt2-cvs

cvs -d$GT2CVS co $GT2PKGS
if test ! $? = 0; then
	echo ""
	echo "cvs checkout of $GT2PKGS failed"
	echo ""
	exit 1
fi
 
cd $BASEDIR/source-trees/cbindings

cvs -d$GT3CVS co $GT3PKGS
if test ! $? = 0; then
	echo ""
	echo "cvs checkout of $GT3PKGS failed"
	echo ""
	exit 1
fi

cd $BASEDIR
./make-packages.pl -no-updates -packages="$PKGLIST"

export GPT_LOCATION=$BASEDIR/gpt-3.0.1
cd $BASEDIR/package-output
$GPT_LOCATION/sbin/gpt-bundle -srcdir=$PWD -bn=globus_chosting -bv=0.1 `ls | sed -e "s|\(.*\)-.*|\1|" | xargs`

if test -z "$GLOBUS_LOCATION"; then
	echo ""
	echo "Setting GLOBUS_LOCATION to $BASEDIR/GT.chosting"
	echo ""
	export GLOBUS_LOCATION=$BASEDIR/GT.chosting
fi

$GPT_LOCATION/sbin/gpt-build globus_chosting-0.1-src_bundle.tar.gz gcc32dbg
