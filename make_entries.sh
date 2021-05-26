#!/usr/bin/bash

cd /tmp/zig/lib/std/

comma=false

echo { # And so it begins.

# all zigs, cut skips './' (start with character 3)
for f in $( find . -name '*.zig' | sort | cut -c 3- )
do
    if [[ $comma == true ]]
    then
        echo , # comma-separate entries
    fi
    echo "\"$f\": {"
    echo '    "description": "",'
    echo '    "hide": false,'
    echo '    "compact": false'
    echo }
    comma=true
done

echo } # And so it ends.
