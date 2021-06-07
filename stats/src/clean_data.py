import os
import re
import sys
import pickle
import pandas as pd
from pandas.core import frame


tmp_dir = "../tmp"
STORE_DIR = "../gen_data/"

def get_mid_dir(proj):
    return f"../mid/{proj}"


def every(times, period=1000):
    if times % period == 0 and times != 0: return True


def parse_mich_qua_line(line):
    pass


def save_mid(name=None, obj=None, dir=tmp_dir):
    assert name is not None, "save_mid needs a name"
    assert obj is not None, "save_mid needs an obj"
    if not os.path.exists(dir): os.mkdir(dir)

    # pandas df to csv
    if type(obj) == frame.DataFrame:
        obj.to_csv(os.path.join(dir, f"{name}.csv"), header=True)
        return

    # others to pkl
    with open(os.path.join(dir, f"{name}.pkl"), "wb") as handle:
        pickle.dump(obj, handle)


def read_mid(filename=None, dir=tmp_dir, columns=None):
    # with suffix
    fitters = ["csv", "pkl"]
    assert filename is not None, "read_mid needs a filename"
    assert filename.split(".")[-1] in fitters, "read_mid file is not in readable format"
    file_path = os.path.join(dir, filename)
    assert os.path.exists(os.path.exists(file_path)), "does not exists"

    obj = None
    if filename.endswith(".csv"):
        obj = pd.read_csv(file_path, names=columns)
    elif filename.endswith(".pkl"):
        with open(file_path, "rb") as handle:
            obj = pickle.load(handle)

    return obj


def get_all_vulns(proj):
    mid_dir = get_mid_dir(proj)
    all_vulns = read_mid(filename="all_vuln_functions.csv", dir=mid_dir, columns=["filename", "func", 'cve', 'hexsha'])
    # all_vulns.drop("cve", axis=1, inplace=True)
    all_vulns.drop_duplicates(inplace=True)
    for i in range(len(all_vulns)):
        if not all_vulns.iloc[i]["filename"].endswith(".c"):
            all_vulns.iloc[i]["filename"] = all_vulns.iloc[i]["filename"] + ".c"
    return all_vulns



def time_sort_vulns(proj):
    vuln_csvs = [
        "vuln-2006-2015-quality-cleaned.csv",
        "vuln-2015-2018-quality-cleaned.csv"
    ]

    results = []
    for f in vuln_csvs:
        proj_data_dir = get_mid_dir(proj)
        f = os.path.join(proj_data_dir, f)
        table = pd.read_csv(f)
        for i in range(len(table)):
            func_id = table.iloc[i]["func_id"]
            try:
                name_file, cve = re.split("_[^_]+_CVE-", func_id)
            except:
                print(func_id)
                continue
            hexsha = re.search("[^_]{40}", func_id)
            if hexsha is not None:
                hexsha = hexsha.group(0)
            else:
                continue
            name = re.split("_[^_]+%", name_file)[0]
            f = name_file[len(name)+1:].replace("%", "/")+".c"
            print(name, f, cve)
            year, num = cve.split("-")
            results.append((name, f, year, num, hexsha))
    return results


# return a list of possible names
def mich_asm(f, fn):
    if f.endswith(".c"): f = f[:-2]
    f = f.replace("/", "%")
    return "_".join([fn, f])


def time_sort_codebase(proj, year):
    f = "codebase-"+str(year)+"-quality-cleaned.csv"
    results = []
    proj_data_dir = get_mid_dir(proj)
    f = os.path.join(proj_data_dir, f)
    table = pd.read_csv(f)

    additional_file = f"{proj}_{year}_normal_extra.csv"
    additional_file = os.path.join(STORE_DIR, additional_file)
    additional_table = pd.read_csv(additional_file)

    table["filepath"]          = ["x" for _ in table["func_id"]]
    table["funcname"]          = ["x" for _ in table["func_id"]]
    table["sec_large_add"]     = [-1 for _ in table["func_id"]]
    table["large_del"]         = [-1 for _ in table["func_id"]]
    table["max_com_mod_span"]  = [-1 for _ in table["func_id"]]
    table["max_com_func_span"] = [-1 for _ in table["func_id"]]
    table["min_contrib_com"]   = [-1 for _ in table["func_id"]]

    for i in range(len(additional_table)):
        filepath = additional_table.iloc[i]["filepath"]
        funcname = additional_table.iloc[i]["funcname"]
        fid = mich_asm(filepath, funcname)
        if fid in table["func_id"].values:
            idx = table.index[table['func_id'] == fid].tolist()[0]
            table.at[idx, "filepath"] = filepath
            table.at[idx, "funcname"] = funcname
            table.at[idx, "sec_large_add"]     = additional_table.iloc[i]["sec_large_add"]
            table.at[idx, "large_del"]         = additional_table.iloc[i]["large_del"]
            table.at[idx, "max_com_mod_span"]  = additional_table.iloc[i]["max_com_mod_span"]
            table.at[idx, "max_com_func_span"] = additional_table.iloc[i]["max_com_func_span"]
            table.at[idx, "min_contrib_com"]   = additional_table.iloc[i]["min_contrib_com"]

    df = table[table["large_del"] != -1]
    df.to_csv(os.path.join(STORE_DIR, f"{proj}_{year}_clean_all.csv"), header=True)


if __name__ == "__main__":
    # time_sort_vulns("FFmpeg")
    proj = sys.argv[1]
    year = int(sys.argv[2])
    time_sort_codebase(proj, year)
