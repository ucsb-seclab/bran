import os
import sys
from datetime import datetime
import pickle
import pandas
import random
import string
import re

training_set_end = datetime(2015, 12, 31, 23, 59, 59)
test_set_end = datetime(2018, 12, 31, 23, 59, 59)

meaningless = ["", " ", "none", "None"]

STORE_PATH = "../gen_data"


def clean(to_clean):
    lower_string = to_clean.lower()
    no_wspace_string = lower_string.strip()
    return no_wspace_string


# -> [(path, funcname, commit, commit_date, author), (n_add, n_del)]
def load_single(project_name, year):
    pkl_path = os.path.join(STORE_PATH, f"{project_name}_{year}.pkl")
    with open(pkl_path, "rb") as f:
        single_rec = pickle.load(f)
    return single_rec


def combine_auth(authconn, name, email):
    name_handle = authconn.get(name, set())
    email_handle = authconn.get(email, set())
    if name_handle is not email_handle:
        if len(name_handle) + len(email_handle) == 0: # both new
            authconn[name] = {name, email}
            authconn[email] = authconn[name]
        elif len(name_handle) == 0:
            authconn[email].add(name)
            authconn[name] = authconn[email]
        elif len(email_handle) == 0:
            authconn[name].add(email)
            authconn[email] = authconn[name]
        else: # merge
            authconn[name] = set.union(authconn[name], authconn[email])
            authconn[email] = authconn[name]
        # if len(authconn[name]) > 10: print(authconn[name])


def raw_years(project_name, years):
    # (file_path, funcname) -> [(n_add, epoch)]
    func_add_recs = dict()
    # (file_path, funcname) -> [(n_del, epoch)]
    func_del_recs = dict()
    # (path, funcname) -> [(commit, epoch)]
    func_commits = dict()
    # hash -> set()
    commit_func_span = dict()
    commit_file_span = dict()
    # (path, funcname) -> [auth.name]
    func_auths = dict()
    # authconn: name/email -> []
    authconn = dict()
    # name/email -> set(epoch)
    auth_count = dict()

    for year in years:
        print(f"getting {year}...")
        recs = load_single(pname, year)
        for commit_info in recs:
            for (path, funcname, c_hash, c_date, auth), (n_add, n_del) in commit_info:
                key = (path, funcname)
                epoch = c_date.timestamp()

                # func
                if key not in func_add_recs:
                    func_add_recs[key] = []
                    func_del_recs[key] = []
                    func_commits[key] = []
                func_add_recs[key].append((n_add, epoch))
                func_del_recs[key].append((n_del, epoch))
                func_commits[key].append((c_hash, epoch))

                # commit
                if c_hash not in commit_func_span:
                    commit_func_span[c_hash] = set()
                    commit_file_span[c_hash] = set()
                commit_func_span[c_hash].add((path, funcname))
                commit_file_span[c_hash].add(path)

                # auth
                auth.name = clean(auth.name)
                auth.email = clean(auth.email)
                if auth.name in meaningless and auth.email in meaningless:
                    auth.name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                    auth.email = auth.name
                elif auth.name in meaningless:
                    auth.name = auth.email
                elif auth.email in meaningless:
                    auth.email = auth.name

                if key not in func_auths: func_auths[key] = []
                func_auths[key].append(auth.name)
                combine_auth(authconn, auth.name, auth.email)
                if auth.name not in auth_count: auth_count[auth.name] = set()
                auth_count[auth.name].add(epoch)

    return func_add_recs, func_del_recs, func_commits, commit_func_span, \
           commit_file_span, func_auths, authconn, auth_count


def get_auth_exp(auth, authconn, authcnt):
    auth_commit_cnt = 0
    for alias in authconn[auth]:
        if alias in authcnt:
            auth_commit_cnt += len(authcnt[alias])
    return auth_commit_cnt


if __name__ == "__main__":
    pname = sys.argv[1]
    end_year = int(sys.argv[2])   # including this year
    # pname = "linux"
    # end_year = 2018

    if pname == "linux":
        years = list(range(2005, end_year+1))
    else:
        years = list(range(2000, end_year+1))

    func_add_recs,\
    func_del_recs,\
    func_commits,\
    commit_func_span,\
    commit_file_span,\
    func_auths,\
    authconn,\
    auth_count = raw_years(pname, years)
    
    auth_experience = dict()
    for auth in auth_count:
        auth_experience[auth] = get_auth_exp(auth, authconn, auth_count)

    # stats
    second_largest_commit_add = dict()
    largest_commit_del = dict()
    max_commit_module_span = dict()
    max_commit_func_span = dict()
    min_contrib_commit = dict()

    for k in func_add_recs:
        ## second largest commit add
        adds = [n_add for n_add, _ in func_add_recs[k]]
        if len(adds) <= 2:
            second_largest_commit_add[k] = 0
        else:
            adds.sort()
            adds.pop()
            second_largest_commit_add[k] = adds.pop()

        ## largest commit deletion
        dels = [n_del for n_del, _ in func_add_recs[k]]
        if len(dels) == 0:
            largest_commit_del[k] = 0
        else:
            dels.sort()
            largest_commit_del[k] = dels.pop()

        commits = func_commits[k]

        ## max commit module span
        module_span = [commit_file_span[c] for c, _ in commits]
        module_span_count = [len(span) for span in module_span]
        max_commit_module_span[k] = max(module_span_count)

        ## max commit func span
        func_span = [commit_func_span[c] for c, _ in commits]
        func_span_count = [len(span) for span in func_span]
        max_commit_func_span[k] = max(func_span_count)

        ## min number of contrib commits
        contrib_exps = [auth_experience[n] for n in func_auths[k]]
        min_contrib_commit[k] = min(contrib_exps)


    to_df_dict = dict()
    ids = list(func_add_recs.keys())
    to_df_dict["filepath"] = [f for f,_ in ids]
    to_df_dict["funcname"] = [fn for _,fn in ids]
    to_df_dict["sec_large_add"] = [second_largest_commit_add[k] for k in ids]
    to_df_dict["large_del"] = [largest_commit_del[k] for k in ids]
    to_df_dict["max_com_mod_span"] = [max_commit_module_span[k] for k in ids]
    to_df_dict["max_com_func_span"] = [max_commit_func_span[k] for k in ids]
    to_df_dict["min_contrib_com"] = [min_contrib_commit[k] for k in ids]

    df = pandas.DataFrame(to_df_dict)
    df.to_csv(os.path.join(STORE_PATH, f"{pname}_{end_year}_normal_extra.csv"), header=True)

    print(f"File saved to {STORE_PATH}")
