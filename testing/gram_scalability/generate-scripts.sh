#!/bin/sh

schedulers="CondorIntelLinux Fork Lsf Pbs"
template="submit-SCHEDULER-mmjfs-test.in"
keyword="SCHEDULER"

for scheduler in $schedulers; do
    filename="submit-$scheduler-mmjfs-test.sh"
    if [ -r $filename ]; then
        rm $filename
    fi
    echo "generating $filename"
    cat $template | sed "s/$keyword/$scheduler/" > $filename
done
