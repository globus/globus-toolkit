#! /bin/sh

./generate_parameter_files.sh
../scripts/globus_build_config.pl --flavor=sweet fum > simple_dep.rslt
diff simple_dep.exp simple_dep.rslt
