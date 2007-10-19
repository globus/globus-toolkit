#! /bin/sh

runReport() {

  if [ -z "$OUTPUT" ] ; then
    echo "Error: Output file not specified" 1>&2
    exit 1
  fi

  REPORT_NAME=$1

  shift

  $GLOBUS_LOCATION/bin/$REPORT_NAME "$@" > $OUTPUT
  if [ $? != 0 ]; then
    echo "Error: Failed to generate the report"
    exit 2
  fi
}

runReport2() {

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

  ant -f $GLOBUS_LOCATION/etc/globus_usage_reports/combined/reports.xml $ANT_TARGET -Din.xml=$OUTPUT
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
mdsusagediff)
        OUTPUT=$PWD/MDSUsageDiffReport.xml
        runReport2 "combined-mdsusagediff-report" "mdsusagediff.xml" "gnuplot-mdsusagediff" "mdsusagediff.gnuplot" "$@"
        ;;
gramusagediff)
        OUTPUT=$PWD/GRAMUsageDiffReport.xml
        runReport2 "combined-gramusagediff-report" "gramusagediff.xml" "gnuplot-gramusagediff" "gramusagediff.gnuplot" "$@"
        ;;
rftusagediff)
        OUTPUT=$PWD/RFTUsageDiffReport.xml
        runReport2 "combined-rftusagediff-report" "rftusagediff.xml" "gnuplot-rftusagediff" "rftusagediff.gnuplot" "$@"
        ;;
gftpusagediff)
        OUTPUT=$PWD/GFTPUsageDiffReport.xml
        runReport2 "combined-gftpusagediff-report" "gftpusagediff.xml" "gnuplot-gftpusagediff" "gftpusagediff.gnuplot" "$@"
        ;;
rlsusagediff)
        OUTPUT=$PWD/RLSUsageDiffReport.xml
        runReport2 "combined-rlsusagediff-report" "rlsusagediff.xml" "gnuplot-rlsusagediff" "rlsusagediff.gnuplot" "$@"
        ;;
rftfreqdist)
        OUTPUT=$PWD/RFTFreqDistReport.xml
        runReport2 "combined-rftfreqdist-report" "rftfreqdist.xml" "gnuplot-rftfreqdist" "rftfreqdist.gnuplot" "$@"
        ;;
gftpfreqdist)
        OUTPUT=$PWD/GFTPFreqDistReport.xml
        runReport2 "combined-gftpfreqdist-report" "gftpfreqdist.xml" "gnuplot-gftpfreqdist" "gftpfreqdist.gnuplot" "$@"
        ;;
rlsfreqdist)
        OUTPUT=$PWD/RLSFreqDistReport.xml
        runReport2 "combined-rlsfreqdist-report" "rlsfreqdist.xml" "gnuplot-rlsfreqdist" "rlsfreqdist.gnuplot" "$@"
        ;;
gramfreqdist)
        OUTPUT=$PWD/GramFreqDistReport.xml
        runReport2 "combined-gramfreqdist-report" "gramfreqdist.xml" "gnuplot-gramfreqdist" "gramfreqdist.gnuplot" "$@"
        ;;
*)
    echo "Unknown report type: $REPORT_TYPE";
    exit 1
    ;;
esac
