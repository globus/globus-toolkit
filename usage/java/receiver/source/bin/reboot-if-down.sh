#!/bin/bash

if [ -z "$GLOBUS_LOCATION" ] ; then
   echo "GLOBUS_LOCATION not set."
   exit 2
fi

#Use ps to check whether receiver is running
count=`ps -ef | grep receiver | grep -c -v "grep receiver"`

#if it isn't, start the receiver:
if [ $count -lt 1 ]
then
    date=`date +%Y%m%d-%H%M%S`
    mv $GLOBUS_LOCATION/receiver.log "$GLOBUS_LOCATION/receiver.log.$date"
    nohup $GLOBUS_LOCATION/bin/globus-usage-receiver &> $GLOBUS_LOCATION/receiver.log &
    #notify that this has occured
    time=`date`
    echo "An automatic check at $time found that the usage-stats was not running, and restarted it." 
    if [ -n "$1" ] ; then 
      echo "${date}: Receiver was not running, and was restarted." | mail -s "Usage-Stats receiver restarted" $1
    fi
fi
