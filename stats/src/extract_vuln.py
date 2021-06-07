import os
import sys
from datetime import datetime
from pydriller import Repository
import pickle
import pandas
import pandas as pd
import random
import string
import re

training_set_end = datetime(2015, 12, 31, 23, 59, 59)
test_set_end = datetime(2018, 12, 31, 23, 59, 59)

meaningless = ["", " ", "none", "None"]

PROJ_PATH = "../data/"
STORE_PATH = "../gen_data/"


def clean(to_clean):
    lower_string = to_clean.lower()
    no_wspace_string = lower_string.strip()
    return no_wspace_string


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


def raw_years_yield(pname, years, targets):
    targets = targets[::-1]
    up_to, key, _ = targets.pop()
    print("NEW:", key)
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
                while c_date >= up_to:
                    # print(up_to)
                    yield func_add_recs, func_del_recs, func_commits, commit_func_span, \
                           commit_file_span, func_auths, authconn, auth_count
                    up_to, _key, _ = targets.pop()
                    print("NEW:", _key)
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


def parse_mich(func_id):
    # print(func_id)
    try:
        name_file, cve = re.split("_[^_]+_CVE-", func_id)
    except:
        import ipdb; ipdb.set_trace()
    hexsha = re.search("_[^_]+_CVE", func_id)
    if hexsha is not None:
        hexsha = hexsha.group(0)
        hexsha = hexsha[:-4]
        hexsha = hexsha[1:]
    else:
        import ipdb; ipdb.set_trace()
    name = re.split("_[^_]+%", name_file)[0]
    f = name_file[len(name)+1:].replace("%", "/")+".c"
    year, num = cve.split("-")
    return name, f, year, num, hexsha


def get_all_vulns(proj):
    vuln_dir = "../mid/"
    vuln_dir = os.path.join(vuln_dir, proj)
    tables = []
    for f in os.listdir(vuln_dir):
        if f.startswith("vuln"):
            fp = os.path.join(vuln_dir, f)
            table = pd.read_csv(fp)
            tables.append(table)
    table = pd.concat(tables)
    table.drop_duplicates(inplace=True)
    return table


def get_features(pname, targets):
    end_year = 2018
    if pname == "linux": years = list(range(2005, end_year+1))
    else: years = list(range(2000, end_year+1))

    gen = raw_years_yield(pname, years, targets)
    for up_to, target_key, _ in targets:
        func_add_recs, \
        func_del_recs, \
        func_commits, \
        commit_func_span, \
        commit_file_span, \
        func_auths, \
        authconn, \
        auth_count = next(gen)

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

        # import ipdb; ipdb.set_trace()
        if target_key not in second_largest_commit_add:
            yield None
        else:
            yield second_largest_commit_add[target_key],\
                   largest_commit_del[target_key], \
                   max_commit_module_span[target_key],\
                   max_commit_func_span[target_key],\
                   min_contrib_commit[target_key]


if __name__ == "__main__":
    pname = sys.argv[1]
    proj_path = os.path.join(PROJ_PATH, pname)
    # pname = "linux"
    # end_year = 2018
    cnt = 0
    table = get_all_vulns(pname)
    table.reset_index(inplace=True)

    targets = []
    for i in range(len(table)):
        func_id = table.iloc[i]["func_id"]
        fn, f, year, num, hexsha = parse_mich(func_id)
        up_to_hash = hexsha
        commit = next(Repository(proj_path, single=up_to_hash).traverse_commits())
        up_to = commit.committer_date
        targets.append((up_to, (f, fn), func_id))
    targets.sort()
    gen = get_features(pname, targets)

    table["filepath"]          = ["x" for _ in table["func_id"]]
    table["funcname"]          = ["x" for _ in table["func_id"]]
    table["sec_large_add"]     = [-1 for _ in table["func_id"]]
    table["large_del"]         = [-1 for _ in table["func_id"]]
    table["max_com_mod_span"]  = [-1 for _ in table["func_id"]]
    table["max_com_func_span"] = [-1 for _ in table["func_id"]]
    table["min_contrib_com"]   = [-1 for _ in table["func_id"]]
    table["year"]   = [-1 for _ in table["func_id"]]

    for i, (up_to, key, func_id) in enumerate(targets):
        print()
        print(i, "/", len(table))
        additional_features = next(gen)
        if additional_features is None: cnt += 1
        # print(additional_features)

        # index = table.loc[table['func_id'] == func_id].index[0]
        fn, f, year, num, hexsha = parse_mich(func_id)
        # up_to_hash = hexsha
        # commit = next(Repository(proj_path, single=up_to_hash).traverse_commits())
        # up_to = commit.committer_date
        # old_additional_features = get_features_old(pname, up_to, key)
        # print("OLD:", key)
        # print(old_additional_features)
        #
        # assert(additional_features == old_additional_features)

        idx = table.loc[table['func_id'] == func_id].index
        print(idx)
        idx = idx[0]
        table.at[idx, "filepath"] = key[0]
        table.at[idx, "funcname"] = key[1]
        if additional_features is not None:
            table.at[idx, "sec_large_add"]     = additional_features[0]
            table.at[idx, "large_del"]         = additional_features[1]
            table.at[idx, "max_com_mod_span"]  = additional_features[2]
            table.at[idx, "max_com_func_span"] = additional_features[3]
            table.at[idx, "min_contrib_com"]   = additional_features[4]
            table.at[idx, "year"]   = year

    print(cnt)
    print(len(table))

    df = table[table["large_del"] != -1]
    df.to_csv(os.path.join(STORE_PATH, f"{pname}_vuln_all.csv"), header=True)

    df_2015 = df[df["year"] <= 2015]
    df_2015.to_csv(os.path.join(STORE_PATH, f"{pname}_vuln_2015.csv"), header=True)
    df_2018 = df[df["year"] > 2015]
    df_2018.to_csv(os.path.join(STORE_PATH, f"{pname}_vuln_2018.csv"), header=True)

    print(f"Vuln data file saved to {STORE_PATH}")

