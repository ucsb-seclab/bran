import json
import sys
import os
import time
import requests

srv_url = sys.argv[1]
GET_REQ_URL = srv_url + '/getchareccve'
SEND_RES_URL = srv_url + '/setcharecresult'
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


def send_data_response(cve_id, output_file, output_zip, exit_status):
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


def run_charecterize_vuln_func(func_extract_output_dir, changing_thresh, github_repo_name,
                               neo4j_ip, neo4j_port, raw_output_txt):
    run_cmd = "java -jar /data/bin/VulnFunctionCharacterizer.jar /repos/kernelmain " + \
              func_extract_output_dir + " " + changing_thresh + " " + github_repo_name + \
              " " + neo4j_ip + " " + neo4j_port + " > " + raw_output_txt + " 2>&1"
    return os.system(run_cmd)


def process_request(req_json):
    cve_id = req_json['CVEID']
    input_zip_cont = req_json['ZIPCONT']
    neo4j_ip = req_json['NEO4JIP']
    changing_thresh = req_json['CHANGTHRESH']
    github_repo_name = req_json["GITREPONAME"]
    neo4j_port = req_json['NEO4JPORT']
    output_folder = req_json['OUTPUT_SUCCESS_FOLDER']

    os.system("mkdir -p " + output_folder)

    raw_output_file = os.path.join(output_folder, cve_id + "_func_charec_raw_output.txt")

    input_zip_file = os.path.join(output_folder, cve_id + ".zip")
    fp = open(input_zip_file, "wb")
    fp.write(input_zip_cont.decode("base64"))
    fp.close()
    # extract the provided zip file
    os.system("cd " + output_folder + "; unzip " + cve_id + ".zip")
    os.system("mv " + output_folder + "/" + cve_id + " " + output_folder + "/tmp")
    os.system("mv " + output_folder + "/tmp/* " + output_folder)
    os.system("rm -rf " + output_folder + "/tmp")

    exit_status = run_charecterize_vuln_func(output_folder, changing_thresh, github_repo_name,
                                             neo4j_ip, neo4j_port, raw_output_file)

    # remove zip file
    os.system("rm -rf " + input_zip_cont)
    # zip the folder
    os.system('cd ' + output_folder + '; zip -r ' + cve_id + '.zip *')

    send_data_response(cve_id, raw_output_file, input_zip_file, exit_status)
    # clean up
    os.system("rm -rf " + output_folder)


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
