#! /bin/sh

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
