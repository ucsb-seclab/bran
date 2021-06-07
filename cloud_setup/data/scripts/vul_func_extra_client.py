import json
import sys
import os
import time
import requests

srv_url = sys.argv[1]
GET_REQ_URL = srv_url + '/getcve'
SEND_RES_URL = srv_url + '/setcveresult'
KILL_SWITCH = srv_url + '/iskill'


def get_next_user():
    try:
        r = requests.get(GET_REQ_URL)
        return json.loads(str(r.text))
    except Exception as e:
        print(str(e))
        return None


def iskill():
    try:
        r = requests.get(KILL_SWITCH)
        return str(r.text) == "KILL"
    except Exception as e:
        print(str(e))
        return None


def send_data_response(cve_id, output_zip, output_file, exit_status):
    output_dict = dict()
    output_dict['CVEID'] = cve_id

    output_res = ''
    if os.path.exists(output_zip):
        fp = open(output_zip, "r")
        output_res = fp.read()
        fp.close()

    output_dict['OUTPUT_ZIP_CONT'] = output_res.encode("base64")

    output_res = ''
    if os.path.exists(output_file):
        fp = open(output_file, "r")
        output_res = fp.read()
        fp.close()

    output_dict['OUTPUT_RAW_CONT'] = output_res.encode("base64")

    output_dict['EXITCODE'] = exit_status

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    print "[+] Sending Response back to server."
    r = requests.post(SEND_RES_URL, data=json.dumps(output_dict), headers=headers)
    resp_from_serv = str(r.text)
    print "[+] Server Says:" + resp_from_serv


def run_extract_vuln_func(cve_commit, output_folder, raw_output_txt):
    run_cmd = "java -jar /data/bin/VulFuncExtractor.jar /repos/kernelmain " + \
              output_folder + " " + cve_commit + " > " + raw_output_txt + " 2>&1"
    return os.system(run_cmd)


def process_request(req_json):
    cve_id = req_json['CVEID']
    cve_commit = req_json['CVECOMMIT']
    output_file = os.path.join("/tmp/workdir", cve_id + ".raw.output")
    output_folder = os.path.join("/tmp/workdir", cve_id)
    os.system("mkdir -p " + output_folder)

    exit_status = run_extract_vuln_func(cve_commit, output_folder, output_file)

    output_zip = os.path.join("/tmp/workdir", cve_id + ".zip")
    os.system('cd /tmp/workdir; zip -r ' + cve_id + '.zip ' + cve_id)
    send_data_response(cve_id, output_zip, output_file, exit_status)
    # clean up
    os.system("rm -rf " + output_folder)
    os.system("rm -rf " + output_file)
    os.system("rm -rf " + output_zip)


while True:
    kill_res = iskill()
    if kill_res is None:
        # sleep for 5 seconds
        print "[+] Sleeping"
        time.sleep(5)
    else:
        if not kill_res:
            next_req = get_next_user()
            if next_req is not None:
                process_request(next_req)
            else:
                print "[*] Request is None"
                time.sleep(10)
        else:
            print "[*] Killed."
