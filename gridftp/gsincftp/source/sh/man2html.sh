#!/bin/sh

cd ../doc/man
for i in *.1 ; do
	echo "----- $i -----"
	eqn -Tascii $i | tbl | nroff -man | rman -f HTML > /tmp/$i.html
done
