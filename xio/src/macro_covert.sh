#! /bin/sh 

file=globus_xio_macro_magic.in
db=$1

if [ "$db" = "D" ]; then
    cat $file | grep --invert-match ^2 | sed 's/\\$//' | sed 's/^1 //' > globus_xio_macro_magic.c
    echo "/* nothing here */" > globus_xio_macro_magic.h
else
    cat $file | grep --invert-match ^1 | sed 's/^2 //' > globus_xio_macro_magic.h
    echo "/* nothing here */" > globus_xio_macro_magic.c
fi


