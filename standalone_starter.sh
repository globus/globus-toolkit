#!/bin/sh                                                            
                                                                      
. VDT_LOCATION/setup.sh

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c VDT_LOCATION/gridftp_hdfs/gridftp.conf -dsi hdfs -no-fork

