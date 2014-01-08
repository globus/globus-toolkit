#! /bin/sh

for d in $(find . -name dirt.sh.in); do
    ./packaging/git-dirt-filter --smudge "$d" < "$d" > /dev/null 
done
