#!/bin/sh                                                            
                                                                      
. VDT_LOCATION/setup.sh

echo $CLASSPATH

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c gridftp.conf -dsi hdfs -no-fork

