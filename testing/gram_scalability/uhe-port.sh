#!/bin/sh

/usr/bin/head ~/.globus/uhe-`uname -n`/log | grep "Service container running at :" | sed "s/..*:\([0-9][0-9]*\)\/ogsa..*/\1/"
