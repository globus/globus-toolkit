#!/bin/sh

VERSION="3.3.0"
TAGOPTS="-t2=HEAD -t3=HEAD"
INSTALLER="gt${VERSION}-preogsi-installer"
GPT="fait_accompli/gpt-3.0.1-src.tar.gz"

mkdir $INSTALLER

./make-packages.pl --trees=gt2,cbindings $TAGOPTS --bundles=globus-resource-management-server,globus-resource-management-sdk,globus-resource-management-client,globus-data-management-server,globus-data-management-sdk,globus-data-management-client,globus-information-services-server,globus-information-services-sdk,globus-information-services-client --version=$VERSION --installer=install-gt3 $@

if [ $? -ne 0 ]; then
        echo "An error occurred."
        exit
fi

mkdir $INSTALLER/bundles
cp bundle-output/*.tar.gz $INSTALLER/bundles
cp bundle-output/install-gt3 $INSTALLER
chmod +x $INSTALLER/install-gt3 
cp $GPT $INSTALLER

rm -fr *-output

./make-packages.pl -n --bundles=schedulers --version=$VERSION

if [ $? -ne 0 ]; then
        echo "An error occurred."
        exit
fi

mkdir $INSTALLER/schedulers
mkdir $INSTALLER/schedulers/gram-reporters
cp package-output/globus_gram_job*.tar.gz  $INSTALLER/schedulers
cp package-output/globus_gram_reporter*.tar.gz  $INSTALLER/schedulers/gram-reporters
