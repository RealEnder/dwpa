#!/bin/bash
# Compress *.txt in current dir and create md5 checksum file
gzip -9 *.txt
for DICT in `ls *.gz`
do
    MD5=`md5sum $DICT`
    MD5="${MD5:0:32}"
    echo -n "$MD5" > "$DICT.md5"
done
