#!/bin/bash

if [ -z "$GLOBUS_LOCATION" ] ; then
   echo "GLOBUS_LOCATION not set."
   exit 2
fi

date=`date "+%Y-%m-%d"`

#Use ps to check whether receiver is running
count=`fgrep $date $GLOBUS_LOCATION/receiver.log | grep -c ERROR`

#if it isn't, start the receiver:
if [ "$count" -ne "0" ]
then
    echo "Found $count errors in receiver log."
    if [ -n "$1" ] ; then 
      echo "${date}: Found $count errors in receiver log." | mail -s "Usage-Stats receiver log errors" $1
    fi
fi
