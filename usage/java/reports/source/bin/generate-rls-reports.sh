#!/bin/sh

REPORT_NAME=rls
REPORT_DESCRIPTION=RLS

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "rls-reports.sh" "domain replica uptime"
