#!/bin/sh

host=$1
port=$2
job_id=$3

if [ -z $host ]; then
    host=`${GLOBUS_LOCATION}/libexec/globus-libc-hostname`
fi
if [ -z $port ]; then
    port=8080
fi

factory="$host:$port/ogsa/services/base/gram/MasterCondorIntelLinuxManagedJobFactoryService"

./kill-job.sh $factory $job_id
