#! /bin/sh

install_pkg () {
if test ! -d "$pkg_dir/$1"; then
    mkdir $pkg_dir/$1
    echo "$1_libraries=\"-l$1 $2\"" > $pkg_dir/$1/build_parameters_sweet
    echo "$1_requires_build=\"$3\"" >> $pkg_dir/$1/build_parameters_sweet
fi
}
if test ! -d ./globus; then
    mkdir ./globus
    mkdir ./globus/etc
    mkdir ./globus/etc/globus_packages
fi

pkg_dir="./globus/etc/globus_packages"

install_pkg foo "-lm -L/usr/local/lib -lX"

install_pkg fee "-lm -L/opt/dum/lib -ldum" "foo"

install_pkg fum "-lm -L/opt/dum/lib -ldee" "foo fee"
