#!/bin/sh

tree=GlobusHEAD

if [ $# -lt 5 ]; then
   echo Usage: $0 dest admin start build status [log]
   echo where
   echo "    dest   = tinderbox destination URL"
   echo "    admin  = The admin contact for this build"
   echo "    start  = startime in perl -e "print time" format"
   echo "    build  = buildname to be used in tinderbox display"
   echo "    status = building, success, build_failed"
   echo "    log    = optional logfile attachment"

   exit 1

fi

cat > tindermail.$$ << EOF

tinderbox: administrator: $2
tinderbox: tree: $tree
tinderbox: starttime: $3
tinderbox: timenow: `perl -e "print time"`
tinderbox: buildname: $4
tinderbox: errorparser: unix
tinderbox: status: $5
tinderbox: END
EOF

if [ x"$6" != "x" ]; then
   cat $6 >> tindermail.$$
fi

./tinderhttp.pl $1 tindermail.$$
# mail -s tinderbox $1 < tindermail.$$
