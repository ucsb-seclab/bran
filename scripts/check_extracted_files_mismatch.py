import os
import csv
import numpy as np

ROOT_DIR="/home/utente/tmp/vuln-linux-2010"

def file_len(fname):
    if os.path.isfile(fname):
        i = -1
        with open(fname) as f:
            for i, l in enumerate(f):
                pass
        if i == -1:
            return 0
        else:
            return i + 1
    else:
        return 0

for name in os.listdir(ROOT_DIR):
	if name.startswith("CVE") and os.path.isdir(os.path.join(ROOT_DIR, name)):
		_, _, files = next(os.walk(ROOT_DIR + "/" + name + "/" + os.listdir(os.path.join(ROOT_DIR, name))[0] + "/old_files"))
		if (file_len(ROOT_DIR + "/" + name + "/" + os.listdir(os.path.join(ROOT_DIR, name))[0]  + "/affected-files.txt" ) != len(files)):
                                      print(name)
                                      print(file_len(ROOT_DIR + "/" + name + "/" + os.listdir(os.path.join(ROOT_DIR, name))[0]  + "/affected-files.txt" ))
                                      print(len(files))
                                      print("found mismatch")

