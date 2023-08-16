#!/usr/bin/env bash

cd "$(dirname $0)"

UNITTEST="./test.txt"

readarray -t unittest < $UNITTEST

cd ..

function TEST()
{
    echo $1
    python3 -m unittest "unit."$1
    echo
}

for unit in "${unittest[@]}"
do
	if [ "$unit" != "" ]; then
        TEST $unit
    fi
done
