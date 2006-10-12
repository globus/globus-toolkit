#!/bin/sh

REPORT_NAME=gram
REPORT_DESCRIPTION=GRAM

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "gram-reports.sh" "jobtype features error domain scheduler"
