#!/bin/sh

factory=$1
job_id=$2

if [ -z $factory ]; then
    echo "ERROR: No factory GSH specified"
    exit
fi

if [ ! -d ./schema ]; then
    /bin/cp -rf $GLOBUS_LOCATION/schema .
fi

begin_time=0
end_time=0

begin_time=`date +%s`
rm -f $logfile
$GLOBUS_LOCATION/bin/managed-job-globusrun -kill $factory/$job_id
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds"
