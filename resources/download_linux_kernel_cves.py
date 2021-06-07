import sh
import json
import os
import multiprocessing


def filter_commits(repo_path, all_commits):
    target_git = sh.git.bake("--no-pager", _cwd=repo_path)
    target_commits = []
    for commit_hash in all_commits:
        try:
            files = target_git.diff("--name-only", commit_hash + "^",
                                    commit_hash).split('\n')[:-1]
            only_modified = target_git.diff("--diff-filter=M", "--name-only",
                                            commit_hash + "^",
                                            commit_hash).split('\n')[:-1]
            if len(files) == 1:
                # Filtering: we only want .c files

                only_modified_c_files = [f for f in filter(lambda s: s.endswith(".c"), only_modified)]

                # if we have only one C file modified.
                if len(only_modified) == len(only_modified_c_files) and len(only_modified) == 1:
                    target_commits.append((commit_hash, only_modified_c_files[0]))
                else:
                    # print "Commit" + commit_hash, "has non-c files and its ignored."
                    pass
            else:
                # self.nlog.log_warn("Commit", commit_hash, "has", len(files), " number of files and its ignored.")
                pass
        except:
                # self.nlog.log_error("Exception occurred while analyzing commit", commit_hash,
                #                    "for repo", self.repo_path)
                pass

    return target_commits


def fetch_commit((repo_path, output_folder, commit_hash)):
    try:
        target_git = sh.git.bake("--no-pager", _cwd=repo_path)
        only_modified = target_git.diff("--diff-filter=M", "--name-only",
                                        commit_hash + "^",
                                        commit_hash).split('\n')[:-1]
        os.system("mkdir -p " + output_folder)

        old_dir = os.path.join(output_folder, "old")
        new_dir = os.path.join(output_folder, "new")

        os.system("mkdir -p " + old_dir)
        os.system("mkdir -p "+ new_dir)

        for f in only_modified:
            oldfile = os.path.join(old_dir, f.replace('/', '_'))
            newfile = os.path.join(new_dir, f.replace('/', '_'))
            target_git.show(commit_hash + "^:" + f, _out=oldfile)
            target_git.show(commit_hash + ":" + f, _out=newfile)
    except:
        print "Bammed up for:" + output_folder


def parse_cve_json(json_file_path, repo_path, output_dir):
    print "[*] Loading Json"
    fp = open(json_file_path, "r")
    cont = fp.read()
    curr_obj = json.loads(cont)
    fp.close()

    single_file_cve = []
    non_single_file_cve = []

    for curr_cve_num in curr_obj:
        print "[*] Processing:" + curr_cve_num
        fixco = curr_obj[curr_cve_num]["fixes"]
        if len(fixco) > 0:
            cu = filter_commits(repo_path, [fixco])
            if len(cu) > 0 and cu[0][0] == fixco:
                single_file_cve.append((curr_cve_num, fixco))
            else:
                non_single_file_cve.append((curr_cve_num, fixco))

    single_file_dir = os.path.join(output_dir, "single_file_cves")
    multi_file_dir = os.path.join(output_dir, "multi_file_cves")

    file_download_jobs = []

    for curr_s in single_file_cve:
        file_download_jobs.append((repo_path, os.path.join(single_file_dir, curr_s[0] + "_" + curr_s[1]), curr_s[1]))

    for curr_s in non_single_file_cve:
        file_download_jobs.append((repo_path, os.path.join(multi_file_dir, curr_s[0] + "_" + curr_s[1]), curr_s[1]))

    print "[*] Downloading all CVE files:" + str(len(file_download_jobs))
    p = multiprocessing.Pool()
    p.map(fetch_commit, file_download_jobs)
    print "[+] Downloaded all CVE files."

parse_cve_json("/home/utente/eclipse-workspace/kerneline/resources/kernel_cves.json", "/home/utente/ucsb/project-stuff/linux", "/home/utente/ucsb/project-stuff/machiry-script-cves")
