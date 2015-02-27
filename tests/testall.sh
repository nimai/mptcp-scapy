#!/bin/bash

# Test server UDP access
def_host=10.2.1.2
def_port=5005

HOST=${2:-$def_host}
PORT=${3:-$def_port}

echo "Starting unit testing"
all=0
fail=0 
for category in join global; do
echo "Beginning unit tests serie: $category"
for t in $category/*; do
    
    echo -n "EXECTEST $t" | nc -u -w1 $HOST $PORT
	$t
	if [ $? -eq 0 ]; then
		echo "Test $t: success"

	else
		echo "Test $t: fail"
		let fail++
	fi
	let all++
done
done

echo "Finished unit testing"
success=`expr $all - $fail`
echo "[Results] On $all tests, $fail failed and $success succeeded"

