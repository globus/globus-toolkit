
#
# source this file to properly set up your environment for globus applications
#

if ( ! $?GLOBUS_LOCATION ) then
    echo "ERROR: environment variable GLOBUS_LOCATION not defined"
    exit 1
endif

if ( $?GLOBUS_PATH ) then
    setenv PATH `echo "$PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    setenv MANPATH `echo "$MANPATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    setenv LD_LIBRARY_PATH `echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
endif

setenv PATH `echo "$PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
setenv MANPATH `echo "$MANPATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
setenv LD_LIBRARY_PATH `echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`

setenv GLOBUS_PATH $GLOBUS_LOCATION
setenv PATH "$GLOBUS_LOCATION/bin:$GLOBUS_LOCATION/sbin:$PATH";

set DELIM
if ( $?MANPATH ) then
    set DELIM=:
endif
setenv MANPATH "$GLOBUS_LOCATION/man$DELIM$MANPATH"

set DELIM=
if ( $?LD_LIBRARY_PATH ) then
    set DELIM=:
endif
setenv LD_LIBRARY_PATH "$GLOBUS_LOCATION/lib$DELIM$LD_LIBRARY_PATH"
