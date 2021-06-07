import pandas as pd
import seaborn as sns
from sklearn import preprocessing
import os
import json
import pickle
import sys
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import matplotlib.pyplot as plt
np.random.seed(0)

min_max_scaler = preprocessing.MinMaxScaler()

STORE_PATH = "../gen_data"
FEATURES = ["fun_loc","fun_cplx","mod_loc","mod_cplx","fun_nChanges","mod_nChanges","fun_nAuth","mod_nAuth","n_input","n_decl","n_coloc_funs","locom","n_sanity_check","n_cast","n_null_ptr","n_ptr_mod","avg_contr_follow","avg_contr_forks","avg_contr_repos","avg_contr_start","avg_contr_watch","sec_large_add","large_del","max_com_mod_span","max_com_func_span","min_contrib_com"]
SAVES = FEATURES+["is_vuln"]
project = sys.argv[1]

n = 6
method = 'bran'
coll_features = {}

def prepare_bran(project):
    codebase_csv = os.path.join(STORE_PATH, f"{project}_2015_clean_all.csv")
    testbase_csv = os.path.join(STORE_PATH, f"{project}_2018_clean_all.csv")
    vuln_train_csv = os.path.join(STORE_PATH, f"{project}_vuln_2015.csv")
    vuln_test_csv = os.path.join(STORE_PATH, f"{project}_vuln_2018.csv")

    base = pd.read_csv(codebase_csv)
    base.sample(frac=1).reset_index(drop=True)
    testbase = pd.read_csv(testbase_csv)

    vuln_train = pd.read_csv(vuln_train_csv)
    vuln_test = pd.read_csv(vuln_test_csv)

    base[base==np.inf]=np.nan
    base.fillna(0, inplace=True)
    base = base[SAVES]
    testbase[base==np.inf]=np.nan
    testbase.fillna(0, inplace=True)
    testbase = testbase[SAVES]
    vuln_train[vuln_train==np.inf]=np.nan
    vuln_train.fillna(0, inplace=True)
    vuln_train = vuln_train[SAVES]
    vuln_test[vuln_test==np.inf]=np.nan
    vuln_test.fillna(0, inplace=True)
    vuln_test = vuln_test[SAVES]

    mid_n = int((len(base)+len(testbase))/2)
    testbase = pd.concat([base[n*len(vuln_train):], testbase])
    testbase.sample(frac=1).reset_index(drop=True)
    testbase = testbase[:mid_n]

    return base[:n*len(vuln_train)], testbase, vuln_train, vuln_test


if __name__ == "__main__":
    base, testbase, vuln_train, vuln_test = prepare_bran(project)

    trainset = pd.concat([base, vuln_train])
    trainset.sample(frac=1).reset_index(drop=True)
    testset = pd.concat([testbase, vuln_test])

    clf = RandomForestClassifier(n_jobs=2, random_state=0, n_estimators=100)
    clf.fit(trainset[FEATURES], trainset["is_vuln"])

    preds = clf.predict_proba(testset[FEATURES])
    gt = testset["is_vuln"].to_numpy()

    n_all = len(gt)
    n_all_vuln = sum(gt)

    def get_res(portion):
        scores = sorted(preds[:,1])
        thr = scores[-int(len(scores)*portion)]
        predictions = preds[:, 1] >= thr
        n_think_are_vuln = sum(predictions)
        # print(n_think_are_vuln)
        n_among_really_vuln = sum(np.logical_and(predictions, gt))
        # print(n_among_really_vuln)
        x = float(n_think_are_vuln)/n_all
        recall = float(n_among_really_vuln)/n_all_vuln
        return x, recall

    for i in range(1,20):
        print(get_res(i/100.0))

    for imp, f in sorted(zip(clf.feature_importances_, FEATURES)):
        if f not in coll_features: coll_features[f] = []
        coll_features[f].append(imp)
        # print(f, imp)

