#!/bin/sh

ps_sleep_count=0
sleep_proc_count=0

#while [ $sleep_proc_count -lt 400 ]; do
while [ 1 ]; do

queue_job_count=`condor_q | grep lane | wc -l - | awk '{ print $1; }'`
echo $queue_job_count queued jobs detected

ps_launch_count=`ps -u lane | grep launch_uhe | wc -l - | awk '{ print $1; }'`
launch_proc_count=`expr $ps_launch_count`
if [ $launch_proc_count -gt 1 ]; then
    echo $launch_proc_count UHEs detected
fi

sleep 10

done

#mail -s "JOBS DONE" pgwynnel@speakeasy.net < /dev/null
#ping 192.168.1.10
