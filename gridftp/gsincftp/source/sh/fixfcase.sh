#!/bin/sh

if [ "$#" -eq 0 ] ; then
	dir="."
else
	dir="$1"
fi

find "$dir" | awk -F'|' '{
	dir=$0;
	base=$0;
	sub(".*/", "", base);
	i = index(dir, base);
	if (i <= 0) {
		dir="";
	} else {
		dir = substr(dir, 1, i - 1);
		sub("/*$", "/", dir);
	}
	i = index(base, ".");
	if (i > 0) {
		s = tolower(substr(base, i));
		if (substr(base, i) != s) {
			r = substr(base, 1, i - 1);
			base = r s;
			printf("echo /bin/mv \"%s\" \"%s%s\"\n", $0, dir, base);
			printf("/bin/mv \"%s\" \"%s%s\"\n", $0, dir, base);
		}
	}
}' | /bin/sh
