#! /bin/sh

if [ ! -d "$GLOBUS_LOCATION" ] ; then
  echo "Error: GLOBUS_LOCATION invalid or not set: $GLOBUS_LOCATION" 1>&2
  exit 1
fi

. $GLOBUS_LOCATION/share/globus_usage_reports/common.sh

runReport "jwscore-container-up-report" "uptime.xml" "gnuplot-uptime" "uptime.gnuplot" "$@"
