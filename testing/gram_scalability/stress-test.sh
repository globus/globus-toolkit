#!/bin/sh

OPTIND=0
while getopts "f:n:v" arg ; do
    if [ $arg = "f" ]; then
        factory=$OPTARG
    elif [ $arg = "n" ]; then
        count=$OPTARG
    elif [ $arg = "v" ]; then
        verbose=1
    fi
done

if [ -z $factory ]; then
    echo "ERROR: No contact string specified"
    exit
fi
if [ -z $count ]; then
    echo "ERROR: No max job count specified"
    exit
fi

index=1
begin_time=0
end_time=0
batch=-batch

logfile="logs/stress-test.log"
rm -f $logfile

while [ $index -le $count ] 
do 
    cat sleep.xml.in | sed -e "s#GLOBUS_LOCATION#$GLOBUS_LOCATION#" -e "s#JOBINDEX#$index#"> sleep.xml
    echo $index >> $logfile

begin_time=`date +%s`
$GLOBUS_LOCATION/bin/managed-job-globusrun $batch -factory $factory -file ./sleep.xml 2>&1 >> $logfile
if [ $? -ne 0 ]; then
    echo "Error on job $index...aborting"
    break
fi
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds" >> $logfile

  index="$(($index + 1))"
done
