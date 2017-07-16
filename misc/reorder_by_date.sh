#!/bin/bash
# Copy files from source directory to target in Y/M/D style

PATTERN="*.cap"

if [ $# -ne 2 ]; then
    echo "$0 [source dir] [target dir]"
    exit 1
fi
if [ ! -r "$1" ]; then
    echo "Source dir $1 not readable!"
    exit 1
fi
if [ ! -w "$2" ]; then
    echo "Target dir $1 not writable!"
    exit 1
fi

PBW=40
SOURCE="$1"
TARGET="$2"
SOURCECNT=$(find "$SOURCE" -maxdepth 1 -type f -name "$PATTERN" -print | wc -l)
TARGETCNT=0
if [ $SOURCECNT -eq 0 ]; then
    echo "Source dir $SOURCE doesn't have files with pattern $PATTERN"
    exit 1
fi

find "$SOURCE" -maxdepth 1 -type f -name "$PATTERN" | while read FILENAME; do
    TARGETCNT=$(($TARGETCNT + 1))
    PROGRESS=$(echo "$PBW/$SOURCECNT*$TARGETCNT" | bc -l) 
    FILL=$(printf "%.0f\n" $PROGRESS)
    if [ $FILL -gt $PBW ]; then
        FILL=$PBW
    fi
    EMPTY=$(($FILL-$PBW))
    PER=$(echo "100/$SOURCECNT*$TARGETCNT" | bc -l)
    PER=$(printf "%0.2f\n" $PER)
    if [ $(echo "$PER>100" | bc) -gt 0 ]; then
        PER="100.00"
    fi
    
    printf "\r["
    printf "%${FILL}s" '' | tr ' ' \#
    printf "%${EMPTY}s" '' | tr ' ' .
    printf "] $PER%%"

    TS=$(date +%Y/%m/%d -r "$FILENAME")
    if [ ! -d "$TARGET/$TS" ]; then
        mkdir -p "$TARGET/$TS"
    fi
    BNFN=$(basename $FILENAME)
    if [ ! -f "$TARGET/$TS/$BNFN" ]; then
        cp -p "$FILENAME" "$TARGET/$TS"
    fi
done
echo
