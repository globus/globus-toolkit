#!/bin/sh

factory=$1
rsl_file=$2

if [ -z $factory ]; then
    echo "ERROR: No factory GSH specified"
    exit
fi
if [ -z $rsl_file ]; then
    echo "ERROR: No rsl file specified"
    exit
fi
begin_time=0
end_time=0
gass_option=-o

begin_time=`date +%s`
rm -f $logfile
$GLOBUS_LOCATION/bin/managed-job-globusrun $gass_option -factory $factory -file $rsl_file
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds"
