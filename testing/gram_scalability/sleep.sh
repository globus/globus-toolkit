#!/bin/sh

duration=$1
sleep_timeout=15
error=`expr $sleep_timeout / 2`
median=`expr $duration + $error`
time_cmd="/bin/date +%s"

echo "Runnung for $median +/- $error seconds"
start_time=`$time_cmd`
current_time=0
lapsed_time=0
while [ $lapsed_time -lt $duration ]; do
    /bin/sleep 15
    echo "looping..."
    current_time=`$time_cmd`
    lapsed_time=`expr $current_time - $start_time`
done
echo "I have woken up after $lapsed_time seconds"
