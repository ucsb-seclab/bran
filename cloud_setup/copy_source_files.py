import os
import sys

if len(sys.argv) < 2:
    print "[?] Usage: " + sys.argv[0] + " <target_docker_image>"
    sys.exit(-1)

dst_folder = sys.argv[1] + "/docker/data"
src_folder = "data"

os.system("mkdir -p " + dst_folder)
print "[*] Copying all python files."
for curr_f in os.listdir(src_folder):
    currfpath = os.path.join(src_folder, curr_f)
    print "[+] Copying:" + currfpath + " to " + dst_folder
    os.system("cp -r " + currfpath + " " + dst_folder)
