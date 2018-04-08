#!/bin/bash

echo "Compress dictionaries(*.txt) in current dir and create inserts for dwpa"

# get base URL
URL=""
REGEX="https?://[-A-Za-z0-9+/%~_!.]*/"
while [[ ! $URL =~ $REGEX ]]
do
  read -p "Enter base URL for dict with trailing /: " URL
done

# check if we have cracked.txt and create it if missing
if [ ! -f cracked.txt ]; then
    echo "password" > cracked.txt
fi

# reset dict.sql
echo -n "" > dict.sql

# create inserts
for DICT in `ls *.txt`
do
    # word count of dict
    WC=$(wc -l < $DICT)
    
    # compress
    gzip -9 < $DICT > $DICT.gz
    
    # md5 of gz dict
    MD5=`md5sum < $DICT.gz`
    MD5="${MD5:0:32}"
    
    echo "INSERT INTO dicts (dpath, dhash, dname, wcount, hits) VALUES ('$URL$DICT.gz', X'$MD5', '${DICT%.txt}', $WC, 0);" | tee -a dict.sql
done
