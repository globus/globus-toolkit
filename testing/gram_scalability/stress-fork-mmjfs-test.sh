#!/bin/sh

host=$1
port=$2
max=$3

factory="$host:$port/ogsa/services/base/gram/MasterForkManagedJobFactoryService"

./stress-test.sh $factory $max
