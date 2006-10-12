#!/bin/sh

REPORT_NAME=gftp
REPORT_DESCRIPTION=GridFTP

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "gftp-reports.sh" "buffer host response stripe"

