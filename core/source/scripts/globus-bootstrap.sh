
if test ! -h globus_automake_targets ; then
    echo "installing globus_automake_targets link"
    ln -s $GLOBUS_LOCATION/share/globus_aclocal/automake_targets \
    globus_automake_targets
fi

if test ! -h globus_automake_rules ; then
    echo "installing globus_automake_rules link"
    ln -s $GLOBUS_LOCATION/share/globus_aclocal/automake_rules \
    globus_automake_rules
fi

if test ! -h globus_automake_doxygen_rules ; then
    echo "installing globus_automake_doxygen_rules link"
    ln -s $GLOBUS_LOCATION/share/globus_aclocal/automake_doxygen_rules \
    globus_automake_doxygen_rules
fi

if test ! -h globus_automake_top_rules ; then
    echo "installing globus_automake_top_rules link"
    ln -s $GLOBUS_LOCATION/share/globus_aclocal/automake_top_rules \
    globus_automake_top_rules
fi

if test ! -h globus_automake_config ; then
    echo "installing globus_automake_config link"
    ln -s $GLOBUS_LOCATION/share/globus_aclocal/automake_config \
    globus_automake_config
fi
