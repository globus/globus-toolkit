#!/bin/sh
######################################################################
#
# gssapi-om-uint-size-test.sh
#
# Make sure sizeof(OM_uint32) is consistent and makes sense.
#
######################################################################

size1=`./gssapi-om-uint-size-test-1`
size2=`./gssapi-om-uint-size-test-2`

if test $size1 -ne $size2 ; then
	echo "gssapi-om-uint-size-test failed."
	echo "Sizes were: $size1 and $size2"
	exit 1
fi

echo "gssapi-om-uint-size-test passed."
exit 0