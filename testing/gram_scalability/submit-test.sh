#!/bin/sh

OPTIND=0
while getopts "f:r:wov" arg ; do
    if [ $arg = "f" ]; then
        factory=$OPTARG
    elif [ $arg = "r" ]; then
        rsl_file=$OPTARG
    elif [ $arg = "w" ]; then
        gass_option=-w
    elif [ $arg = "o" ]; then
        gass_option=-o
    elif [ $arg = "v" ]; then
        verbose=1
    fi
done

if [ -z $factory ]; then
    echo "ERROR: No factory GSH specified"
    exit
fi
if [ -z $rsl_file ]; then
    echo "ERROR: No rsl file specified"
    exit
fi

if [ ! -d ./schema ]; then
    /bin/cp -rf $GLOBUS_LOCATION/schema .
fi

cat ${rsl_file}.in | sed -e "s#GLOBUS_LOCATION#$GLOBUS_LOCATION#" > $rsl_file 


begin_time=0
end_time=0

begin_time=`date +%s`
$GLOBUS_LOCATION/bin/managed-job-globusrun $gass_option -factory $factory -file $rsl_file
end_time=`date +%s`
echo "Time taken for managed-job-globusrun: `expr $end_time - $begin_time` Seconds"
