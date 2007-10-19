#!/bin/sh

REPORT_NAME=combined
REPORT_DESCRIPTION=combined

BASEDIR=`dirname $0`

. $BASEDIR/generate-reports.common

createReport "combined-reports.sh" "mdsusagediff gramusagediff rftusagediff rlsusagediff gftpusagediff gramfreqdist rftfreqdist rlsfreqdist gftpfreqdist"
