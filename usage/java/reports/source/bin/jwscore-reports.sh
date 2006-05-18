#! /bin/sh

if [ ! -d "$GLOBUS_LOCATION" ] ; then
  echo "Error: GLOBUS_LOCATION invalid or not set: $GLOBUS_LOCATION" 1>&2
  exit 1
fi

. $GLOBUS_LOCATION/share/globus_usage_reports/common.sh

REPORT_TYPE=$1
shift

case $REPORT_TYPE in
uptime)
        runReport "jwscore-container-up-report" "uptime.xml" "gnuplot-uptime" "uptime.gnuplot" "$@"
        ;;
uptime2)
        runReport "jwscore-container-up-2-report" "uptime.xml" "gnuplot-uptime" "uptime.gnuplot" "$@"
        ;;
longuptime)
        runReport "jwscore-container-long-up-report" "longuptime.xml" "gnuplot-long-uptime" "longuptime.gnuplot" "$@"
        ;;
longuptime2)
        runReport "jwscore-container-long-up-2-report" "longuptime.xml" "gnuplot-long-uptime" "longuptime.gnuplot" "$@"
        ;;
event)
        runReport "jwscore-container-event-report" "event.xml" "gnuplot-event" "event.gnuplot" "$@"
        ;;
container)
        runReport "jwscore-container-report" "container.xml" "gnuplot-container" "uniqueservices.gnuplot containers.gnuplot services.gnuplot" "$@"
        ;;
*)
    echo "Unknown report type: $REPORT_TYPE";
    exit 1
    ;;
esac
