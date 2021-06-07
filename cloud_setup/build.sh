#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_image_folder>"
    exit 1
fi
if [ ! -d "$1" ]; then
    echo "Provided image folder: $1 doesn't exist."
    exit 2
fi

(
python copy_source_files.py $1
cd $1/docker
docker build -t git.seclab.cs.ucsb.edu:4567/warmik/kerneline:$1 .
docker push git.seclab.cs.ucsb.edu:4567/warmik/kerneline:$1
)

