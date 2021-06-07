import argparse
import sys
import subprocess
import os
from log_stuff import *
import multiprocessing
import json


def setup_args():
    parser = argparse.ArgumentParser()

    required_named = parser

    required_named.add_argument('-l', action='store', dest='llvm_bc_out',
                                help='Destination directory where all the generated bitcode files are stored.',
                                required=True)

    required_named.add_argument('-o', action='store', dest='interesting_funcs',
                                help='Path to the file containing initial seed functions.', required=True)

    return parser


def get_bin_path(bin_name):
    out_p = subprocess.check_output('which ' + bin_name, shell=True)
    return out_p.strip()


def get_cg_dump_jsons(bc_path):
    to_ret = []
    if os.path.isdir(bc_path):
        for curr_dir in os.listdir(bc_path):
            curr_d_p = os.path.join(bc_path, curr_dir)
            to_ret.extend(get_cg_dump_jsons(curr_d_p))
    else:
        if bc_path.endswith(".bc"):
            target_output_file = bc_path + ".cgoutput.json"
            if os.path.exists(target_output_file):
                to_ret.append(target_output_file)
    return to_ret


def get_called_func_list(curr_json):
    to_ret = {}
    try:
        fp = open(curr_json, "r")
        all_cont = fp.read()
        curr_json_obj = json.loads(all_cont)
        fp.close()

        for curr_func_di in curr_json_obj["CallGraphInfo"]:
            curr_f_name = curr_func_di.keys()[0]
            called_funcs = curr_func_di[curr_f_name]
            if len(called_funcs) > 0:
                to_ret[curr_f_name] = called_funcs
    except Exception as e:
        print("Problem ocurred while analyzing:" + curr_json)
    return to_ret


def get_whole_func_map(all_jsons):
    log_info("Processing:", len(all_jsons), " jsons in multiprocessing mode.")
    p = multiprocessing.Pool()
    called_fun_dict = p.map(get_called_func_list, all_jsons)
    log_success("Finished processing jsons.")
    log_info("Organizing results.")
    final_func_map = {}
    for curr_di in called_fun_dict:
        for curr_f in curr_di:
            for called_fun in curr_di[curr_f]:
                if called_fun not in final_func_map:
                    final_func_map[called_fun] = set()
                final_func_map[called_fun].add(curr_f)
    log_success("Finished processing results.")
    return final_func_map


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    llvm_bc_out = parsed_args.llvm_bc_out
    interesting_func_file = parsed_args.interesting_funcs
    if (not os.path.exists(llvm_bc_out)) or (not os.path.exists(interesting_func_file)):
        log_error("One of the provided paths doesn't exist:", llvm_bc_out, interesting_func_file)
        sys.exit(-1)

    curr_num_lines = sum(1 for line in open(interesting_func_file, "r"))
    initial_num_functions = curr_num_lines
    all_cg_jsons = get_cg_dump_jsons(llvm_bc_out)
    total_cg_map = get_whole_func_map(all_cg_jsons)
    curr_init_funcs = set()
    fp = open(interesting_func_file, "r")
    all_lines = fp.readlines()
    fp.close()
    for currl in all_lines:
        currl = currl.strip()
        curr_init_funcs.add(currl)

    num_iter = 1
    processed_functions = set()
    new_funcs_to_process = set(curr_init_funcs)
    while len(new_funcs_to_process):
        log_info("Current Iteration:", num_iter, ", Num functions:", len(curr_init_funcs))
        num_iter += 1
        curr_func_set = new_funcs_to_process
        new_funcs_to_process = set()
        for curr_func_name in curr_func_set:
            if curr_func_name not in processed_functions:
                processed_functions.add(curr_func_name)
                if curr_func_name in total_cg_map:
                    new_funcs_to_process.update(total_cg_map[curr_func_name])
                    curr_init_funcs.update(total_cg_map[curr_func_name])

        sanitized_funcs = set()
        for curr_f in new_funcs_to_process:
            if curr_f not in processed_functions:
                sanitized_funcs.add(curr_f)

        new_funcs_to_process = sanitized_funcs

    log_success("Got total number of functions:", len(curr_init_funcs),
                " from initial functions:", initial_num_functions)

    log_info("Writing all updated functions to:", interesting_func_file)
    fp = open(interesting_func_file, "w")
    for curr_f in curr_init_funcs:
        fp.write(curr_f + "\n")
    fp.close()


if __name__ == "__main__":
    main()
