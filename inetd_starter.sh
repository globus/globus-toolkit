#!/bin/sh                                                            
                                                                      
. /opt/osg/osg-100/setup.sh
. /home/brian/software/dsi_bones/myenv

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c /home/brian/software/dsi_bones/gridftp-inetd.conf -dsi hdfs > /tmp/gridftp-out
