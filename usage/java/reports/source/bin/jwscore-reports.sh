#! /bin/sh

runReport() {

  REPORT_NAME=$1
  REPORT_OUTPUT=$2
  ANT_TARGET=$3
  PLOT_FILES=$4  

  shift
  shift
  shift
  shift

  OUTPUT=$PWD/$REPORT_OUTPUT

  $GLOBUS_LOCATION/bin/$REPORT_NAME "$@" > $OUTPUT
  if [ $? != 0 ]; then
    echo "Error: Failed to generate the report"
    exit 2
  fi

  ant -f $GLOBUS_LOCATION/etc/globus_usage_reports/reports.xml $ANT_TARGET -Din.xml=$OUTPUT
  if [ $? != 0 ]; then
    echo "Error: Failed to generate gnuplot files"
    exit 3
  fi

  gnuplot $PLOT_FILES
  if [ $? != 0 ]; then
    echo "Error: Failed to generate report graphs"
    exit 3
  fi
}

### MAIN ###

if [ ! -d "$GLOBUS_LOCATION" ] ; then
  echo "Error: GLOBUS_LOCATION invalid or not set: $GLOBUS_LOCATION" 1>&2
  exit 1
fi

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
