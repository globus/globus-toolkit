#!/bin/sh

add_ctrlZ=0

es=1
if [ $# -eq 0 ] ; then
	exec tr -d '\015\032'
elif [ ! -f "$1" ] ; then
	echo "Not found: $1" 1>&2
else
	for f in "$@" ; do
		if awk '{ printf("%s\r\n", $0);} END { if (Z == "1") printf("%s", "\032");}' "Z=$add_ctrlZ" < "$f" > "$f.tmp" ; then
			if cmp "$f" "$f.tmp" > /dev/null ; then
				rm -f "$f.tmp"
			else
				touch -r "$f" "$f.tmp"
				if mv "$f" "$f.bak" ; then
					if mv "$f.tmp" "$f" ; then
						rm -f "$f.bak"
						es=$?
						echo "  converted $f"
					else
						rm -f "$f.tmp"
					fi
				else
					rm -f "$f.tmp"
				fi
			fi
		else
			rm -f "$f.tmp"
		fi
	done
fi
