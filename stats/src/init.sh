#!/bin/bash

WORKDIR=/home/mdy/repo/bran
DATADIR=$WORKDIR/data
GENDIR=$WORKDIR/gen_data

echo "mkdir..."
mkdir -p $DATADIR
mkdir -p $GENDIR

echo "cloning repos..."
git clone https://github.com/wireshark/wireshark $DATADIR/wireshark
git clone https://github.com/torvalds/linux $DATADIR/linux
git clone https://github.com/FFmpeg/FFmpeg $DATADIR/FFmpeg
git clone https://github.com/openssl/openssl $DATADIR/openssl
