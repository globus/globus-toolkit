#!/bin/sh

cp gsiftp-hdfs /etc/xinetd.d/
echo "gsiftphdfs  5000/tcp" >> /etc/services
/etc/init.d/xinetd restart

