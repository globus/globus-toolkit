#! /bin/sh

./generate_parameter_files.sh
../scripts/globus_build_config.pl --flavor=sweet --ldflags="-lm -L/home/mystuff/lib -lXm" fum > simple_dep.rslt
diff simple_dep.exp simple_dep.rslt
