
#
# source this file to properly set up your environment for globus applications
#

if ( ! $?GLOBUS_LOCATION ) then
    echo "ERROR: environment variable GLOBUS_LOCATION not defined"
    exit 1
endif

if ( ! $?MANPATH ) then
    setenv MANPATH
endif

if ( ! $?LD_LIBRARY_PATH ) then
    setenv LD_LIBRARY_PATH
endif

if ( ! $?SASL_PATH ) then
    setenv SASL_PATH
endif

if ( $?GLOBUS_PATH ) then
    setenv PATH `echo "$PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    setenv MANPATH `echo "$MANPATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    setenv LD_LIBRARY_PATH `echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
    setenv SASL_PATH `echo "$SASL_PATH" | sed -e "s%:$GLOBUS_PATH[^:]*%%g" -e "s%^$GLOBUS_PATH[^:]*:\{0,1\}%%"`
endif

setenv PATH `echo "$PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
setenv MANPATH `echo "$MANPATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
setenv LD_LIBRARY_PATH `echo "$LD_LIBRARY_PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`
setenv SASL_PATH `echo "$SASL_PATH" | sed -e "s%:$GLOBUS_LOCATION[^:]*%%g" -e "s%^$GLOBUS_LOCATION[^:]*:\{0,1\}%%"`

setenv GLOBUS_PATH "$GLOBUS_LOCATION"
setenv PATH "$GLOBUS_LOCATION/bin:$GLOBUS_LOCATION/sbin:$PATH";

set DELIM
if ( "X$MANPATH" != "X" ) then
    set DELIM=:
    setenv MANPATH "$GLOBUS_LOCATION/man$DELIM$MANPATH"
endif


set DELIM=
if ( "X$LD_LIBRARY_PATH" != "X" ) then
    set DELIM=:
endif
setenv LD_LIBRARY_PATH "$GLOBUS_LOCATION/lib$DELIM$LD_LIBRARY_PATH"

set DELIM=
if ( "X$SASL_PATH" != "X" ) then
    set DELIM=:
endif
setenv SASL_PATH "$GLOBUS_LOCATION/lib/sasl$DELIM$SASL_PATH"

