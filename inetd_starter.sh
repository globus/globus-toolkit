#!/bin/sh                                                            
                                                                      
. /opt/osg/osg-100-test/setup.sh

exec $GLOBUS_LOCATION/sbin/globus-gridftp-server -c /opt/osg/osg-100-test/gridftp_hdfs/gridftp-inetd.conf -dsi hdfs
