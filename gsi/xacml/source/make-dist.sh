#! /bin/sh

version=''

while [ "$version" = "" ]; do
    read version
done

distdir="xacml-$version"

rm -rf $distdir

mkdir $distdir
if [ ! -r gsoap_2.7.9i.tar.gz ]; then
    curl -O http://superb-east.dl.sourceforge.net/sourceforge/gsoap2/gsoap_2.7.9i.tar.gz
fi

cp gsoap_2.7.9i.tar.gz $distdir
make dist;
cp xacml-1.0.tar.gz $distdir
doxygen
(cd ../test; ./configure; make dist)
cp ../test/xacml_test-1.0.tar.gz $distdir

cp html/* $distdir
cp build.sh $distdir

tar zcf $distdir.tar.gz $distdir
