#!/bin/sh

max=$1
count=1
begin_time=0
end_time=0
#manager_type=Pbs
manager_type=Fork
factory_host=promptu.mcs.anl.gov
factory_port=31415
batch=-batch

logfile="logs/stress-test.log"
#logfile="/dev/null"
rm -f $logfile

while [ $count -le $max ] 
do 
  echo $count >> $logfile

begin_time=`date +%s`
#$GLOBUS_LOCATION/bin/managed-job-globusrun $batch -factory $factory_host:$factory_port -type $manager_type -file ./sleep.xml 2>&1 >> $logfile &
$GLOBUS_LOCATION/bin/managed-job-globusrun $batch -factory $factory_host:$factory_port -type $manager_type -file ./sleep.xml 2>&1 >> $logfile
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds" >> $logfile

  count="$(($count + 1))"
done
