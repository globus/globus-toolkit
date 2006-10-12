#!/bin/sh

REPORT_NAME=jwscore
REPORT_DESCRIPTION="Java WS Core"

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "jwscore-reports.sh" "uptime longuptime container"
