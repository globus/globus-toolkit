#!/bin/sh

REPORT_NAME=rft
REPORT_DESCRIPTION=RFT

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "rft-reports.sh" "file domain"
