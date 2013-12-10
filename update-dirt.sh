#! /bin/sh

find . -name dirt.sh.in -exec sh -c "./packaging/git-dirt-filter --smudge {} < {} > /dev/null" \;
