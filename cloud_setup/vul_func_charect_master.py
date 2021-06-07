from flask import Flask, request
import json
from threading import Lock
import os
import random
import sys
import datetime

app = Flask(__name__)

curr_lock = Lock()
all_requs = []
processing_reqs = []
completed_reqs = []
errored_reqs = []

MASTER_START_TIME = None
OUTPUT_SUCCESS_FOLDER = "/home/utente/ucsb-workspace/kerneline/cloud_setup/output"
OUTPUT_ERROR_FOLDER = "/home/utente/ucsb-workspace/kerneline/cloud_setup/error"
# TODO: change this
NEOIP = "192.168.59.56"
NEOPORT = "7687"
CHANGETHRESH = "2"
GITREPONAME = "torvalds/linux"


def get_next_req():
    global curr_lock
    global all_requs
    to_ret = None
    with curr_lock:
        if len(all_requs) > 0:
            to_get_idx = random.randint(0, len(all_requs) - 1)
            to_ret = all_requs[to_get_idx]
            if to_get_idx == 0:
                all_requs = all_requs[1:]
            else:
                all_requs = all_requs[0:to_get_idx] + all_requs[to_get_idx + 1:]
    return to_ret


def add_processing_req(cve_id):
    global curr_lock
    global processing_reqs
    with curr_lock:
        processing_reqs.append(cve_id)


def remove_proecessing_cve(cve_id):
    global curr_lock
    global processing_reqs
    with curr_lock:
        pr_id = processing_reqs.index(cve_id)
        if pr_id == 0:
            processing_reqs = processing_reqs[1:]
        else:
            processing_reqs = processing_reqs[0:pr_id] + processing_reqs[pr_id + 1:]


def add_errored_req(cve_id):
    global curr_lock
    global errored_reqs
    remove_proecessing_cve(cve_id)
    with curr_lock:
        errored_reqs.append(cve_id)


def add_completed_req(cve_id):
    global curr_lock
    global completed_reqs
    remove_proecessing_cve(cve_id)
    with curr_lock:
        completed_reqs.append(cve_id)


def print_cve_stats():
    global curr_lock
    global all_requs
    global processing_reqs
    global completed_reqs
    global errored_reqs
    global MASTER_START_TIME
    curr_time = datetime.datetime.now() - MASTER_START_TIME
    speed = ((len(completed_reqs) + len(errored_reqs)) * 1.0) / (curr_time.total_seconds())
    print "[+] CVE Commits: Completed: " + str(len(completed_reqs)) + \
          ", Processing:" + str(len(processing_reqs)) + ", Pending:" + str(len(all_requs)) + \
          ", Errored:" + str(len(errored_reqs)) + \
          ", Speed:" + str(speed) + " per sec"


@app.route('/getchareccve', methods=['GET'])
def get_next_cve():
    """
        Get next CVE which needs to be processed
    """
    global NEOIP
    global NEOPORT
    global CHANGETHRESH
    global GITREPONAME
    next_req = get_next_req()
    if next_req is None:
        print "[+] No Request"
        print_cve_stats()
        return "NOREQ"

    cve_zip_file_fp = open(next_req[1], "r")
    zip_file_cont = cve_zip_file_fp.read().encode("base64")
    cve_zip_file_fp.close()

    to_send_req = {'CVEID': next_req[0],
                   'ZIPCONT': zip_file_cont,
                   'NEO4JIP': NEOIP,
                   'NEO4JPORT':NEOPORT,
                   'CHANGTHRESH': CHANGETHRESH,
                   'GITREPONAME': GITREPONAME,
                   'OUTPUT_SUCCESS_FOLDER': OUTPUT_SUCCESS_FOLDER}
    print "[+] Sending Seed User:" + str(next_req)
    add_processing_req(next_req[0])
    print_cve_stats()
    return json.dumps(to_send_req)


def save_result_cont(cve_id, raw_cont, raw_zip_cont, base_folder):
    tar_folder = os.path.join(base_folder, cve_id)
    os.system("mkdir -p " + tar_folder)
    fp = open(os.path.join(tar_folder, cve_id + ".zip"), "wb")
    fp.write(raw_zip_cont)
    fp.close()

    fp = open(os.path.join(tar_folder, cve_id + ".raw.output"), "w")
    fp.write(raw_cont)
    fp.close()


@app.route('/setcharecresult', methods=['POST'])
def process_set_cve_result():
    """
    process result of a request
    """
    global OUTPUT_SUCCESS_FOLDER
    global OUTPUT_ERROR_FOLDER
    try:
        res_json = json.loads(str(request.data))
        if 'CVEID' in res_json:
            cve_id = res_json['CVEID']
            raw_cont = res_json['OUTPUT_RAW_CONT'].decode("base64")
            raw_zip_cont = res_json['OUTPUT_ZIP_CONT'].decode("base64")
            exit_code = res_json['EXITCODE']
            if exit_code == 0:
                add_completed_req(cve_id)
                save_result_cont(cve_id, raw_cont, raw_zip_cont, OUTPUT_SUCCESS_FOLDER)
            else:
                add_errored_req(cve_id)
                save_result_cont(cve_id, raw_cont, raw_zip_cont, OUTPUT_ERROR_FOLDER)
            print_cve_stats()
    except Exception as e:
        print "[?] Exception occurred:" + str(e.message)
        pass

    return "ALLOK"


@app.route('/')
def index():
    """
    Home handler
    """

    return "KERNELINE_MASTER_SAYS_HELLO"


@app.route('/iskill')
def is_exit():
    """
    kill switch
    """

    return "NOKILL"


# Run the app.
if __name__ == '__main__':
    global all_requs
    global MASTER_START_TIME
    cve_base_res_folder = sys.argv[1]
    for curr_cve_folder in os.listdir(cve_base_res_folder):
        target_zip_file = os.path.join(os.path.join(cve_base_res_folder, curr_cve_folder),
                                       curr_cve_folder + ".zip")
        if os.path.exists(target_zip_file):
            all_requs.append((curr_cve_folder, target_zip_file))
        else:
            print "[!] Expected zip file:" + target_zip_file + " not present. Ignoring."

    MASTER_START_TIME = datetime.datetime.now()

    app.run(host='0.0.0.0', debug=True, port=8080)
