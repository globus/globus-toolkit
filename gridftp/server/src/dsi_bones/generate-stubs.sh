#! /bin/sh

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 


if [ "X$1" = "X" ]; then
    echo "generate-stubs <dsi name> <flavor>"
    exit 1
fi

if [ "X$2" = "X" ]; then
    echo "generate-stubs <dsi name> <flavor>"
    exit 1
fi

if [ "X$GLOBUS_LOCATION" = "X" ]; then
    echo "$GLOBUS_LOCATION must be defined"
    exit 1
fi

name=$1
flavor=$2

date=`date +%s`

$GLOBUS_LOCATION/bin/globus-makefile-header -flavor=$flavor globus_gridftp_server > makefile_header

sed -e "s/@DSI@/$name/g" -e "s/@DATE@/$date/g" globus_gridftp_server_dsi.c.in > globus_gridftp_server_$name.c
sed -e "s/@DSI@/$name/g" -e "s/@FLAVOR@/$flavor/g" Makefile.in > Makefile
