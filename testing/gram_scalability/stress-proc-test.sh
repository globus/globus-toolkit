#!/bin/sh

max=$1
count=0
begin_time=0
end_time=0

logfile="logs/stress-test.log"
#logfile="/dev/null"

while [ $count -ne $max ] 
do 
  echo $count >> $logfile

  sleep 100000 &

  count="$(($count + 1))"
done
