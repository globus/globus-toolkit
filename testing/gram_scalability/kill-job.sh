#!/bin/sh

OPTIND=0
while getopts "u:v" arg ; do
    if [ $arg = "u" ]; then
        url=$OPTARG
    elif [ $arg = "v" ]; then
        verbose=1
    fi
done

if [ -z $url ]; then
    echo "ERROR: No job URL specified"
    exit
fi

if [ $verbose ]; then
    echo job URL: $url
fi

if [ ! -d ./schema ]; then
    /bin/cp -rf $GLOBUS_LOCATION/schema .
fi

begin_time=0
end_time=0

begin_time=`date +%s`
$GLOBUS_LOCATION/bin/managed-job-globusrun -kill $url
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds"
