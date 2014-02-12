#! /bin/sh
portfile="$(basename $0).port"
rm -f "${portfile}"
./test_server > "${portfile}" &
i=0
while [ ! -s "${portfile}" ]; do
    sleep 1;
    i=$(($i + 1))
    if [ $i -eq 10 ]; then
        kill %1
        exit 1
    fi
done
$(basename $0 .sh) --host localhost $(cat ${portfile})
kill %1
