#! /bin/sh

runReport() {

  if [ -z "$OUTPUT" ] ; then
    echo "Error: Output file not specified" 1>&2
    exit 1
  fi

  REPORT_NAME=$1

  shift

  time $GLOBUS_LOCATION/bin/$REPORT_NAME "$@" > $OUTPUT
  if [ $? != 0 ]; then
    echo "Error: Failed to generate the report"
    exit 2
  fi
}

generateReportSub() {

  if [ -z "$OUTPUT" ] ; then
    echo "Error: Output file not specified" 1>&2
    exit 1
  fi

  COMPONENT=$1
  ANT_TARGET=$2
  PLOT_FILES=$3

  shift
  shift
  shift

  ant -f $GLOBUS_LOCATION/etc/globus_usage_reports/$COMPONENT/reports.xml $ANT_TARGET -Din.xml=$OUTPUT
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

generateHistogramReport() {
  generateReportSub "common" "gnuplot-histogram" "histograms.gnuplot"
}

generateSlotsReport() {
  generateReportSub "common" "gnuplot-slots" "slots.gnuplot"
}

generateRangedReport() {
  generateReportSub "common" "gnuplot-ranged" "ranged.gnuplot"
}


### MAIN ###

if [ ! -d "$GLOBUS_LOCATION" ] ; then
  echo "Error: GLOBUS_LOCATION invalid or not set: $GLOBUS_LOCATION" 1>&2
  exit 1
fi

if [ ! "$GLOBUS_OPTIONS" ] ; then
  export GLOBUS_OPTIONS=-Xmx512m
fi

REPORT_TYPE=$1
shift

case $REPORT_TYPE in
buffer)
	OUTPUT=$PWD/GFTPBufferReport.xml
	runReport "gftp-buffer-report" "$@"
	generateRangedReport
	generateHistogramReport
	;;

host)
        OUTPUT=$PWD/GFTPHostReport.xml
        runReport "gftp-host-report" "$@"
	generateHistogramReport
	generateSlotsReport
        ;;

response)
        OUTPUT=$PWD/GFTPResponseReport.xml
        runReport "gftp-response-report" "$@"
        generateHistogramReport
        generateSlotsReport
        ;;

stripe)
        OUTPUT=$PWD/GFTPStripeReport.xml
        runReport "gftp-stripe-report" "$@"
        generateHistogramReport
        generateSlotsReport
        ;;

*)
    echo "Unknown report type: $REPORT_TYPE";
    exit 1
    ;;
esac
