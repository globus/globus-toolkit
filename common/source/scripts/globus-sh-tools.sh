
if test -z "$GLOBUS_SH_VARIABLES_SET" ; then
    
    . ${GLOBUS_LOCATION}/libexec/globus-sh-tools-vars.sh
    
    # export all commands:

    for _var in `set|${GLOBUS_SH_GREP-grep} "^GLOBUS_SH"| \
        ${GLOBUS_SH_SED} -n '/^GLOBUS_SH/s/=.*$//p' `
    do
        export ${_var}
    done
    GLOBUS_SH_VARIABLES_SET="Y"
    export GLOBUS_SH_VARIABLES_SET


    # end of config file
fi






























