error()
{
    echo ""
    echo "ERROR: bootstrap failed!"
    echo ""
    exit 1
}


# check for autotools

for program in libtoolize automake aclocal autoconf autoheader
    do
    ($program --version ) > /dev/null 2>&1 || { 
    echo "ERROR: $program not found" >&2
    exit 1
    }
done

# Always include globus macros
config="$aclocal_includes -I $GLOBUS_LOCATION/share/globus_aclocal"

# test for local macros
if test -d "./config"; then
    config="$config -I ./config"
fi

# test to see if GPT macros are in a seperate location
if test ! -f "$GLOBUS_LOCATION/share/globus_aclocal/gpt_autoconf_macros.m4"; then
    if test "x$GPT_LOCATION" = "x"; then
        echo "ERROR Globus Packaging Tools not found" >&2
        echo "ERROR either set GPT_LOCATION or install them in $GLOBUS_LOCATION" >&2
        exit 1
    else
        config="$config -I $GPT_LOCATION/share/gpt/aclocal"
    fi
fi

if test "x$GPT_LOCATION" = "x"; then
    GPT_LOCATION=$GLOBUS_LOCATION
fi

if test ! -h pkgdata/Makefile.am ; then
    echo "installing Makefile.am in the pkgdata directory"
    ln -s $GPT_LOCATION/share/gpt/amdir/pkgdata_Makefile.am \
    pkgdata/Makefile.am
fi

echo "running aclocal $config"
#echo 'running: ' `which aclocal`
aclocal $config || error

if test -f acconfig.h ; then
#echo 'running: ' `which autoheader`
echo "running autoheader"
    autoheader || error
fi

echo "running libtoolize --copy --force"
#echo 'running: ' `which libtoolize`
libtoolize --copy  --force|| \
  libtoolize --copy --force  || error

echo "running automake --copy -add-missing --foreign"
#echo 'running: ' `which automake`
automake --copy --add-missing --foreign || \
  automake --copy --add-missing --foreign  || error

echo "running gpt_create_automake_rules --excludes=doxygen"
$GPT_LOCATION/sbin/gpt_create_automake_rules --excludes=doxygen || error


echo "running autoconf"
#echo 'running: ' `which autoconf`
autoconf || error


