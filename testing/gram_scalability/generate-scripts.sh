#!/bin/sh

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

    template="stress-SCHEDULER-mmjfs-test.in"
    filename="stress-$scheduler-mmjfs-test.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
done
