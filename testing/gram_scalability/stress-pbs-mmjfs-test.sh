#!/bin/sh

host=$1
port=$2
max=$3
if [ -z $host ]; then
    echo "ERROR: No host specified"
    exit
fi
if [ -z $port ]; then
    echo "ERROR: No port specified"
    exit
fi
if [ -z $max ]; then
    echo "ERROR: No max job count specified"
    exit
fi

factory="$host:$port/ogsa/services/base/gram/MasterPbsManagedJobFactoryService"

./stress-test.sh $factory $max
