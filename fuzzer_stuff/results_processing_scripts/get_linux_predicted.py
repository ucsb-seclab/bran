"""
Gets all the functions predicted as vulnerable for linux kernel
from the output produced by michelas tool.
"""
import os
import sys
import json
import multiprocessing


def is_json_interesting(json_file_path):
    if "-predictions" in json_file_path and json_file_path.endswith(".json"):
        bname = os.path.basename(json_file_path)
        if "_linux_" in bname:
            return True
    return False


def get_all_interesting_json_files(curr_path):
    if os.path.isfile(curr_path) and is_json_interesting(curr_path):
        return [curr_path]
    retval = []
    if os.path.isdir(curr_path):
        for curr_d in os.listdir(curr_path):
            child_full_path = os.path.join(curr_path, curr_d)
            retval.extend(get_all_interesting_json_files(child_full_path))
    return retval


def get_all_funcs(json_path):
    fp = open(json_path, "r")
    all_cont = fp.read()
    currj = json.loads(all_cont)
    fp.close()
    to_ret = set()
    all_predictions = currj["vuln_predictions"]
    for curr_fun_name in all_predictions:
        score = all_predictions[curr_fun_name]
        if score >= 0.8:
            cnam = "_".join(curr_fun_name.split("%")[0].split("_")[:-1])
            to_ret.add(cnam)
    return to_ret


results_path = sys.argv[1]
output_file = sys.argv[2]
all_files = get_all_interesting_json_files(results_path)
print("[*] Got:" + str(len(all_files)) + " to process.")
p = multiprocessing.Pool()
target_funcs = set()
print("[*] Processing in multiprocessing mode.")
for curr_res in p.map(get_all_funcs, all_files):
    target_funcs.update(curr_res)
print("[*] Writing output to:" + output_file)
fp = open(output_file, "w")
for curr_fu in target_funcs:
    fp.write(curr_fu + "\n")
fp.close()
