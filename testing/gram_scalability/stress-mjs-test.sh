#!/bin/sh

max=$1
count=0
begin_time=0
end_time=0
manager_type=Fork

logfile="logs/stress-test.log"
#logfile="/dev/null"

while [ $count -ne $max ] 
do 
  echo $count >> $logfile

begin_time=`date +%s`
$GLOBUS_LOCATION/bin/managed-job-globusrun -personal -batch -factory http://140.221.36.11:45678/ogsa/services/base/gram/${manager_type}ManagedJobFactoryService -file ./sleep.xml 2>&1 >> $logfile
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds" >> $logfile

  count="$(($count + 1))"
done
