import os
import csv
import zipfile
import shutil

IN_DIR="/home/utente/ucsb-workspace/kerneline/cloud_setup/output_org"
OUT_DIR="/home/utente/ucsb-workspace/kerneline/cloud_setup/output"

for filename in os.listdir(IN_DIR):
    zip_ref = zipfile.ZipFile(IN_DIR + "/" + filename + "/" + filename + ".zip", 'r')
    zip_ref.extractall(OUT_DIR)
    commits = os.listdir(OUT_DIR + "/" + filename + "/" + filename)
    for c in commits:
        shutil.move(OUT_DIR + "/" + filename + "/" + filename + "/" + c, OUT_DIR + "/" + filename)
    
    shutil.rmtree(OUT_DIR + "/" + filename + "/" + filename, False, None)
    zip_ref.close()