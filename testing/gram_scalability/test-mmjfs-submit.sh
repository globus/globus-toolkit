#!/bin/sh

factory=$1
if [ -z $factory ]; then
    echo "ERROR: No factory GSH specified"
    exit
fi
begin_time=0
end_time=0
gass_option=-w

logfile="logs/submit-test.log"
#logfile="/dev/null"

begin_time=`date +%s`
rm -f $logfile
#$GLOBUS_LOCATION/bin/managed-job-globusrun -proxy ./x509up_u876 -factory $factory -file ./echo.xml 2>&1 > $logfile
#$GLOBUS_LOCATION/bin/managed-job-globusrun $gass_option -factory $factory -file ./echo.xml 2>&1 > $logfile
$GLOBUS_LOCATION/bin/managed-job-globusrun $gass_option -factory $factory -file ./echo.xml
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds" >> $logfile
