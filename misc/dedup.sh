#!/bin/bash
# Deduplicate *.txt dicts in current dir
for F1 in `ls -S *.txt | tac`
do
    echo "Sort and uniq $F1"
    sort "$F1" | uniq > "$F1.sorted"
    PASS=1
    for F2 in `ls -S *.txt | tac`
    do
        if [[ PASS -eq 1 ]]; then
            if [[ "$F1" == "$F2" ]]; then
                PASS=0
            fi
            continue
        fi
        echo "Sort and uniq $F2"
        sort "$F2" | uniq > "$F2.sorted"
        echo "Filter $F1 and $F2"
        comm -13 "$F1.sorted" "$F2.sorted" > "$F2"
        rm "$F2.sorted"
    done
    echo "Sort $F1 by line length"
    perl -e 'print sort { length $a <=> length $b } <>' "$F1.sorted" > "$F1"
    rm "$F1.sorted"
done
