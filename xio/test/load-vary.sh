#!/bin/sh
command=$1
max_load=10
ctr=0
while [ 1 ] ; do
  for max in `seq 1 $max_load` ; do
    for i in `seq 1 $max` ; do
      echo "spawning $i"
      $command > test_output/load_vary.log.$ctr & 
      let ctr=$ctr+1
    done
    echo -n "waiting... "
    wait
    echo "done"
  done
done
