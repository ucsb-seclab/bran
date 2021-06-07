#!/bin/bash

# wireshark 98-
# linux 05- the kernel version is from 2.6.12
# FFmpeg 00-
# openssl 98-

START=2016
END=2018

if [[ "$1" == "linux" ]]; then
    START=2005
fi

for (( i=$START; i<=$END; i++ ))
do
   # echo $1 $i
   python collect.py $1 $i &
   sleep 60
done
