#!/bin/sh                                                            
                                                                      
. /opt/osg/osg-100/setup.sh
. myenv

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c gridftp.conf -dsi hdfs -no-fork
