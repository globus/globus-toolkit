#!/bin/sh

ps_sleep_count=0
sleep_proc_count=0

#while [ $sleep_proc_count -lt 400 ]; do
while [ 1 ]; do

ps_sleep_count=`ps -u lane | grep sleep.sh | wc -l - | awk '{ print $1; }'`
sleep_proc_count=`expr $ps_sleep_count`
echo $sleep_proc_count sleep procs detected

ps_launch_count=`ps -u lane | grep launch_uhe | wc -l - | awk '{ print $1; }'`
launch_proc_count=`expr $ps_launch_count`
if [ $launch_proc_count -gt 1 ]; then
    echo $launch_proc_count UHEs detected
fi

sleep 2

done
