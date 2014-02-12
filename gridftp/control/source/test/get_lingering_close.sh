#! /bin/sh
portfile="$(basename $0).port"
rm -f "${portfile}"
./test_server > "${portfile}" &
serverpid=$!
i=0
while [ ! -s "${portfile}" ]; do
    sleep 1;
    i=$(($i + 1))
    if [ $i -eq 10 ]; then
        [ ${serverpid:-0} -gt 0 ] && kill -0 $serverpid && kill $serverpid
        exit 1
    fi
done
$(basename $0 .sh) --host localhost $(cat ${portfile})
([ ${serverpid:-0} -gt 0 ] && kill -0 $serverpid && kill $serverpid) || true
