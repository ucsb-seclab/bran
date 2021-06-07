import argparse
import sys
import subprocess
import os
from log_stuff import *
import multiprocessing

FORCE_CREATE = True


def setup_args():
    parser = argparse.ArgumentParser()

    required_named = parser

    required_named.add_argument('-l', action='store', dest='llvm_bc_out',
                                help='Destination directory where all the generated bitcode files are stored.',
                                required=True)

    required_named.add_argument('-s', action='store', dest='cg_func_dumper_so',
                                help='Path to the llvm pass so which helps in '
                                     'dumping call-graph info.', required=True)

    return parser


def get_bin_path(bin_name):
    out_p = subprocess.check_output('which ' + bin_name, shell=True)
    return out_p.strip()


def get_cg_finder_cmds(opt_path, bc_path, so_file):
    to_ret = []
    if os.path.isdir(bc_path):
        for curr_dir in os.listdir(bc_path):
            curr_d_p = os.path.join(bc_path, curr_dir)
            to_ret.extend(get_cg_finder_cmds(opt_path, curr_d_p, so_file))
    else:
        if bc_path.endswith(".bc"):
            if FORCE_CREATE:
                target_output_file = bc_path + ".cgoutput.json"
                os.system("rm " + target_output_file)
            target_output_file = bc_path + ".cgoutput.json"
            if not os.path.exists(target_output_file):
                to_run_command = opt_path + " -load " + so_file + " -cgdumpjson -outputFile=" + \
                                 target_output_file + " " + bc_path
                to_ret.append(to_run_command)
    return to_ret


def run_command(curr_cmd):
    os.system(curr_cmd)


def run_whole_interesting(all_cmds):
    log_info("Running:", len(all_cmds), "cg dumper commands in multiprocessing mode.")
    p = multiprocessing.Pool()
    p.map(run_command, all_cmds)
    log_success("Finished running cg dumper commands.")


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    opt_path = get_bin_path("opt")
    llvm_bc_out = parsed_args.llvm_bc_out
    func_so = parsed_args.cg_func_dumper_so
    if (not os.path.exists(llvm_bc_out)) or \
            (not os.path.exists(func_so)):
        log_error("One of the provided paths doesn't exist:", llvm_bc_out, func_so)
        sys.exit(-1)

    all_cmds = get_cg_finder_cmds(opt_path, llvm_bc_out, func_so)
    run_whole_interesting(all_cmds)


if __name__ == "__main__":
    main()
