#!/bin/sh

old=`pwd`
for f in \
	./configure.in \
	sio/configure.in \
	Strn/configure.in \
	libncftp/configure.in \
; do
	if [ -f "$f" ] ; then
		dir=`dirname "$f"`
		echo "----- $dir -----"
		dir="$HOME/src/ncftpd/$dir"
		cd "$dir"
		autoheader
		autoconf
		cd "$old" || exit 1
	fi
done
