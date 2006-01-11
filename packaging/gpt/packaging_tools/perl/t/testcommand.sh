#!/bin/sh

echo "I have been work soo hard"
echo "I made a booboo" >&2

if test "x$1" = "xerror"; then
    echo "Fatal booboo" >&2
    exit 1
fi

exit 0