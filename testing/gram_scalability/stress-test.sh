#!/bin/sh

factory=$1
max=$2
if [ -z $factory ]; then
    echo "ERROR: No contact string specified"
    exit
fi
if [ -z $max ]; then
    echo "ERROR: No max job count specified"
    exit
fi

cat sleep.xml.in | sed -e "s#GLOBUS_LOCATION#$GLOBUS_LOCATION#" > sleep.xml

count=1
begin_time=0
end_time=0
batch=-batch

logfile="logs/stress-test.log"
rm -f $logfile

while [ $count -le $max ] 
do 
  echo $count >> $logfile

begin_time=`date +%s`
$GLOBUS_LOCATION/bin/managed-job-globusrun $batch -factory $factory -file ./sleep.xml 2>&1 >> $logfile
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds" >> $logfile

  count="$(($count + 1))"
done
