#!/bin/bash

if [ -z "$1" ] ; then
   echo "Must specify list name."
   exit 1
fi

if [ -z "$GLOBUS_LOCATION" ] ; then
   echo "GLOBUS_LOCATION not set."
   exit 2
fi

$GLOBUS_LOCATION/bin/globus-usage-babysitter clear | mail -s "Daily Globus Usage-Stats Update" "$@"

