#!/bin/sh

. $GLOBUS_LOCATION/libexec/globus-sh-tools.sh

schedulers="CondorIntelLinux Fork Lsf Pbs"
keyword="SCHEDULER"

for scheduler in $schedulers; do
    template="submit-SCHEDULER-mmjfs-test.in"
    filename="submit-$scheduler-mmjfs-test.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
    chmod +x $filename

    template="stress-SCHEDULER-mmjfs-test.in"
    filename="stress-$scheduler-mmjfs-test.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
    chmod +x $filename

    template="deactivation-SCHEDULER-mmjfs-test.in"
    filename="deactivation-$scheduler-mmjfs-test.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
    chmod +x $filename

    template="kill-SCHEDULER-mjfs-job.in"
    filename="kill-$scheduler-mjfs-job.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
    chmod +x $filename
done
