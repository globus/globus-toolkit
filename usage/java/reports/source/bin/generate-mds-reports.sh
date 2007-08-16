#!/bin/sh

REPORT_NAME=mds
REPORT_DESCRIPTION=MDS

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "mds-reports.sh" "registration domain"
