VERSION="3.9.3"
TAGOPTS="-t2=HEAD -t3=HEAD"
INSTALLER="gt${VERSION}-gridftp-source-installer"
GPT="fait_accompli/gpt-3.2autotools2004-src.tar.gz"

mkdir $INSTALLER

./make-packages.pl --trees=gt2 $TAGOPTS --bundles=globus-data-management-server,globus-data-management-sdk,globus-data-management-client --version=$VERSION --installer=install-gridftp $@

if [ $? -ne 0 ]; then
   echo "ERROR"
   exit 1
fi

mkdir $INSTALLER/bundles
cp bundle-output/*.tar.gz $INSTALLER/bundles
cp bundle-output/install-gridftp $INSTALLER
chmod +x $INSTALLER/install-gridftp 
cp $GPT $INSTALLER
rm -fr *-output

mkdir $INSTALLER/tests
./make-packages.pl -n --bundles=prews-test --version=$VERSION
cp bundle-output/*.tar.gz $INSTALLER/tests
