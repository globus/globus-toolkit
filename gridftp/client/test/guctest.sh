#!/bin/sh

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

runs=1
srcpath="/tmp/src/"
dstpath="/tmp/dst/"
file="file://"
ftp="gsiftp://localhost:5000"
ftp2="gsiftp://localhost:5000"
out="~/errors/"

guc="globus-url-copy"
priv="-dcpriv"
safe="-dcsafe"
modee="-fast"
dbg="-dbg"
nodcau="-nodcau"
off="-off 10"
len="-len 439"
notpt="-notpt"
cont="-c"

testset=0
function runtest() {
    let testset=testset+1;
    echo "set $testset: running $1 to $2 test with options: ${!3} ${!4} ${!5} ${!6} ${!7} ${!8} ${!9} ${!10} ${!11}"

    i=0
    failed=0
    while [ $i -lt $runs ]; do
        let i=i+1; 
        echo "**********************************************" > ${out}temp
        echo "**********************************************" >> ${out}temp
         echo "set $testset: running $1 to $2 test with options: ${!3} ${!4} ${!5} ${!6} ${!7} ${!8} ${!9} ${!10} ${!11}" >> ${out}temp
        echo $guc -dbg ${!3} ${!4} ${!5} ${!6} ${!7} ${!8} ${!9} ${!10} ${!11} ${!1}$srcpath ${!2}$dstpath >> ${out}temp
        $guc ${!3} ${!4} ${!5} ${!6} ${!7} ${!8} ${!9} ${!10} ${!11} ${!1}$srcpath ${!2}$dstpath
        if [ $? -ne 0 ]; then
            echo "Test $1 to $2 with options: ${!3} ${!4} ${!5} ${!6} ${!7} ${!8} ${!9} ${!10} ${!11} FAILED" >> ${out}temp
            cat ${out}temp >> ${out}test${testset}-$$
            let failed=failed+1; 	
        fi    
    done
    if [ $failed -gt 0 ]; then
 	echo "set: $testset: $failed/$runs tests FAILED, log at ${out}test${testset}-$$"
    else
        echo "set $testset: all $runs tests completed successfully"
    fi
}

for src in ftp file; do
    for dst in ftp2 file; do
    for opt1 in "" modee; do
      for opt2 in "" safe priv; do
       for opt3 in "" nodcau; do
               for opt4 in "" len; do
                       for opt5 in "" off; do
                               for opt6 in "" cont; do
                                       for opt7 in "" notpt; do
          runtest $src $dst $opt1 $opt2 $opt3 $opt4 $opt5 $opt6 $opt7
      done
    done
  done
done
done
done
done
done
done
