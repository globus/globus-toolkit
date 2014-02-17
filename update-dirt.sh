#! /bin/sh

if ! git rev-parse --show-toplevel > /dev/null 2>&1; then
    echo "Unable to update dirt.sh" 1>&2
fi

for d in $(find . -name dirt.sh.in); do
    ./packaging/git-dirt-filter --smudge "$d" < "$d" > /dev/null 
done
