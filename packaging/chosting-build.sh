#!/bin/sh

BASEDIR=$PWD
GT2PKGS="core common xio gsi callout user_env side_tools mds/libtool tarfiles"
GT3PKGS=chosting

PKGLIST=\
globus_axiscpp,\
globus_expat,\
globus_axiscpp_wsdl2ws,\
globus_axiscpp_transport_stdio,\
globus_axiscpp_server_engine,\
globus_axiscpp_transport_http,\
globus_axiscpp_client_engine,\
globus_axiscpp_client,\
globus_client_CounterService,\
globus_service_CounterService,\
globus_client_CounterService_test,\
globus_service_container,\
globus_core,\
globus_common,\
globus_common_setup,\
globus_user_env,\
globus_xio,\
globus_proxy_utils,\
globus_gssapi_gsi,\
gssapi_error,\
globus_gss_assist,\
globus_callout,\
globus_libtool,\
globus_gsi_proxy_core,\
globus_gsi_credential,\
globus_gsi_callback,\
globus_gsi_sysconfig,\
globus_gsi_cert_utils,\
globus_openssl_module,\
globus_gsi_proxy_ssl,\
globus_gsi_openssl_error,\
globus_proxy_wrapper,\
globus_openssl,\
globus_gcs_b38b4d8c_setup

#globus_axiscpp_stdio_server_test,\
#globus_axiscpp_http_server_test,\

if test ! -d $BASEDIR/source-trees; then
	mkdir $BASEDIR/source-trees
fi

if test ! -d $BASEDIR/source-trees/cbindings; then
	mkdir $BASEDIR/source-trees/cbindings
fi

if test ! -d $BASEDIR/source-trees/gt2-cvs; then
	mkdir $BASEDIR/source-trees/gt2-cvs
fi

if test ! -d $BASEDIR/source-trees/autotools; then
	mkdir $BASEDIR/source-trees/autotools;
fi


#if test -z "$CVSROOT"; then
#	echo ""
#	echo "ERROR: Please set CVSROOT to your standard GT2/3 checkout location"
#	echo ""
#	exit 1
#fi


CVSCHECK=`echo $CVSROOT | sed -e "s|.*\(:\).*|\1|"`
if test -z "$CVSCHECK"; then
        CVSBASE=:pserver:anonymous@cvs.globus.org
else
	CVSBASE=`echo $CVSROOT | sed -e "s|\(.*\):.*|\1|"`
fi

GT2CVS=$CVSBASE:/home/globdev/CVS/globus-packages

cd $BASEDIR/source-trees/gt2-cvs

cvs -d$GT2CVS co $GT2PKGS
if test ! $? = 0; then
	echo ""
	echo "cvs checkout of $GT2PKGS failed. check CVSROOT env."
	echo ""
	exit 1
fi
 
cd $BASEDIR/source-trees/cbindings

cvs -d$GT2CVS co $GT3PKGS
if test ! $? = 0; then
	echo ""
	echo "cvs checkout of $GT3PKGS failed"
	echo ""
	exit 1
fi

cd $BASEDIR/source-trees/autotools

cvs -d$GT2CVS co autotools side_tools
if test ! $? = 0; then
	echo ""
	echo "cvs checkout of $GT2CVS failed"
	echo ""
	exit 1
fi

# check for globus autotools
autoloc=`type autoconf | sed -e "s|autoconf is ||"`
autopath=`echo $autoloc | sed -e "s|/bin/autoconf$||"`
if test -d "$autopath/openssl_tools"; then
	autotools="-noautotools"
else
        autotools=""
fi

cd $BASEDIR
./make-packages.pl $autotools --no-updates -packages="$PKGLIST"
if test ! $? = 0; then
	echo ""
	echo "ERROR: make-packages.pl failed."
	echo ""
	exit 1
fi

export GPT_LOCATION=$BASEDIR/gpt-3.0.1
cd $BASEDIR/package-output
$GPT_LOCATION/sbin/gpt-bundle -srcdir=$PWD -bn=globus_chosting -bv=0.1 `ls | sed -e "s|\(.*\)-.*|\1|" | xargs`
if test ! $? = 0; then
	echo ""
	echo "Failed to create chosting bundle."
	echo ""
	exit 1
fi

echo "GLOBUS LOCATION IS: :${GLOBUS_LOCATION}:"

if test -z "$GLOBUS_LOCATION"; then
	echo ""
	echo "Setting GLOBUS_LOCATION to $BASEDIR/GT.chosting"
	echo ""
	export GLOBUS_LOCATION=$BASEDIR/GT.chosting
	mkdir $GLOBUS_LOCATION
	$GPT_LOCATION/sbin/gpt-build -force -nosrc gcc32dbg
fi

echo "GLOBUS_LOCATION IS: :${GLOBUS_LOCATION}:"

$GPT_LOCATION/sbin/gpt-build -force globus_chosting-0.1-src_bundle.tar.gz gcc32dbg
if test ! $? = 0; then
	echo ""
	echo "Failed to build chosting bundle."
	echo ""
	exit 1
fi
