#!/bin/bash
# Deduplicate *.txt in current dir
F1=""
for DICT in `ls -S *.txt | tac`
do
    if [[ "$F1" == "" ]]; then
        F1="$DICT"
        continue
    fi
    F2="$DICT"
    echo "Sortand uniq $F1 and $F2"
    sort "$F1" | uniq > "$F1.sorted"
    sort "$F2" | uniq > "$F2.sorted"
    echo "Filter $F2"
    comm -13 "$F1.sorted" "$F2.sorted" > "$F2"
    mv "$F1.sorted" "$F1"
    rm "$F2.sorted"
    F1="$DICT"
done
