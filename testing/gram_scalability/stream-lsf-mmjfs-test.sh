#!/bin/sh

host=$1
port=$2

if [ -z $host ]; then
    echo "ERROR: No host specified"
    exit
fi
if [ -z $port ]; then
    port=8080
fi

factory="$host:$port/ogsa/services/base/gram/MasterLsfManagedJobFactoryService"

./submit-test.sh $factory ./date-stream.xml -w
