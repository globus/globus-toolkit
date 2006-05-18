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
