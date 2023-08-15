#!/usr/bin/env bash

cd "$(dirname $0)"

UNITTEST="./unittest.txt"

readarray -t unittest < $UNITTEST

cd "../src"

function TEST()
{
    echo $1
    python3 -m unittest $1
    echo
}

for unit in "${unittest[@]}"
do
	if [ "$unit" != "" ]; then
        TEST $unit
    fi
done
