import argparse
import sys
import subprocess
import os
from .log_stuff import *
import multiprocessing


def setup_args():
    parser = argparse.ArgumentParser()

    required_named = parser

    required_named.add_argument('-l', action='store', dest='llvm_bc_out',
                                help='Destination directory where all the generated bitcode files are stored.',
                                required=True)

    required_named.add_argument('-o', action='store', dest='interesting_funcs',
                                help='Path to the file containing initial seed functions.', required=True)

    required_named.add_argument('-s', action='store', dest='func_detector_so',
                                help='Path to the llvm pass so which helps in '
                                     'finding the interesting functions.', required=True)

    return parser


def get_bin_path(bin_name):
    out_p = subprocess.check_output('which ' + bin_name, shell=True)
    return out_p.strip()


def get_interesting_function_finder_cmds(opt_path, bc_path, so_file, txt_file):
    to_ret = []
    if os.path.isdir(bc_path):
        for curr_dir in os.listdir(bc_path):
            curr_d_p = os.path.join(bc_path, curr_dir)
            to_ret.extend(get_interesting_function_finder_cmds(curr_d_p, so_file, txt_file))
    else:
        if bc_path.endswith(".bc"):
            to_run_command = opt_path + " -load " + so_file + " -infufi -interFunctionList=" + txt_file + " " + bc_path
            to_ret.append(to_run_command)
    return to_ret


def run_command(curr_cmd):
    os.system(curr_cmd)


def run_whole_interesting(all_cmds):
    log_info("Running:", len(all_cmds), "function finder commands in multiprocessing mode.")
    p = multiprocessing.Pool()
    p.map(run_command, all_cmds)
    log_success("Finished running function finder commands.")


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    opt_path = get_bin_path("opt")
    llvm_bc_out = parsed_args.llvm_bc_out
    interesting_func_file = parsed_args.interesting_funcs
    func_so = parsed_args.func_detector_so
    if (not os.path.exists(llvm_bc_out)) or (not os.path.exists(interesting_func_file)) or \
            (not os.path.exists(func_so)):
        log_error("One of the provided paths doesn't exist:", llvm_bc_out, interesting_func_file, func_so)
        sys.exit(-1)

    curr_num_lines = sum(1 for line in open(interesting_func_file, "r"))
    initial_num_functions = curr_num_lines
    all_cmds = get_interesting_function_finder_cmds(opt_path, llvm_bc_out, func_so, interesting_func_file)
    run_whole_interesting(all_cmds)
    new_num_lines = sum(1 for line in open(interesting_func_file, "r"))
    log_info("Running in a fixed point manner.")
    while new_num_lines > curr_num_lines:
        curr_num_lines = new_num_lines
        run_whole_interesting(all_cmds)
        new_num_lines = sum(1 for line in open(interesting_func_file, "r"))

    log_success("Expanded to:", new_num_lines, " functions, while "
                                               "initial number of functions are:", initial_num_functions)


if __name__ == "__main__":
    main()
