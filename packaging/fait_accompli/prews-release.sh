VERSION="3.9.3"
TAGOPTS="-t2=HEAD -t3=HEAD"
INSTALLER="gt${VERSION}-prews-source-installer"
GPT="fait_accompli/gpt-3.2autotools2004-src.tar.gz"

mkdir $INSTALLER

./make-packages.pl --trees=gt2 $TAGOPTS --bundles=globus-resource-management-server,globus-resource-management-sdk,globus-resource-management-client,globus-data-management-server,globus-data-management-sdk,globus-data-management-client,globus-information-services-server,globus-information-services-sdk,globus-information-services-client --version=$VERSION --installer=install-prews $@

if [ $? -ne 0 ]; then
   echo "ERROR"
   exit 1
fi

mkdir $INSTALLER/bundles
cp bundle-output/*.tar.gz $INSTALLER/bundles
cp bundle-output/install-prews $INSTALLER
chmod +x $INSTALLER/install-prews 
cp $GPT $INSTALLER
rm -fr *-output

mkdir $INSTALLER/tests
./make-packages.pl -n --bundles=prews-test --version=$VERSION
cp bundle-output/*.tar.gz $INSTALLER/tests

rm -fr *-output
./make-packages.pl -n --bundles=schedulers --version=$VERSION
mkdir $INSTALLER/schedulers
mkdir $INSTALLER/schedulers/gram-reporters
cp package-output/globus_gram_job*.tar.gz  $INSTALLER/schedulers
cp package-output/globus_gram_reporter*.tar.gz  $INSTALLER/schedulers/gram-reporters

