
#
# source this file to properly set up your environment for globus applications
#

if [ -z "$GLOBUS_LOCATION" ]; then
    echo "ERROR: environment variable GLOBUS_LOCATION not defined"  1>&2
    exit 1
fi

if [ -n "$GLOBUS_PATH" ]; then
    PATH=`echo "$PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    MANPATH=`echo "$MANPATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    LD_LIBRARY_PATH=`echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
fi

PATH=`echo "$PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
MANPATH=`echo "$MANPATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
LD_LIBRARY_PATH=`echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`

GLOBUS_PATH=$GLOBUS_LOCATION
PATH="$GLOBUS_LOCATION/bin:$GLOBUS_LOCATION/sbin:$PATH";

DELIM=
if [ -n "$MANPATH" ]; then
    DELIM=:
fi
MANPATH="$GLOBUS_LOCATION/man$DELIM$MANPATH"

DELIM=
if [ -n "$LD_LIBRARY_PATH" ]; then
    DELIM=:
fi
LD_LIBRARY_PATH="$GLOBUS_LOCATION/lib$DELIM$LD_LIBRARY_PATH"

export GLOBUS_PATH PATH MANPATH LD_LIBRARY_PATH
