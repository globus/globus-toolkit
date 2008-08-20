#!/bin/bash
create_from_url=./handle_create_from_url_test
file=/etc/group

if [ ! -x $create_from_url ]; then
    echo "Could not find test program: $create_from_url"
    exit;
fi

# Make a copy so RW access is possible
tempfile=/tmp/`basename $file`.$$

$create_from_url file:/etc/group file:flags=r > $tempfile
diff /etc/group $tempfile > /dev/null

if [ ! $? -eq 0 ]; then
    echo "test failed: diff does not match"
    rc=1
else
    echo "test succeeded: diff matches"
    rc=0
fi

rm $tempfile

exit $rc
