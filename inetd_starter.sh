#!/bin/sh                                                            
                                                                      
. VDT_LOCATION/setup.sh

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c VDT_LOCATION/gridftp_hdfs/gridftp-inetd.conf -dsi hdfs
