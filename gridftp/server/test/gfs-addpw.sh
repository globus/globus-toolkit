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


filename=$1
username=$2
if [ "X$1" == "X" ]; then
    echo "gfs-addpw.sh <password file> <user name>"
    exit 1
fi
if [ "X$2" == "X" ]; then
    username=`whoami`
fi
home_dir=$GLOBUS_LOCATION
shell=/bin/sh
uid=`id -u`
gid=`id -g`


hash=`openssl passwd $3`

if [ $? != 0 ]; then
    echo "passwords don't match"
    exit 1
fi 

echo "$username:$hash:$uid:$gid::$home_dir:$shell" >> $filename
