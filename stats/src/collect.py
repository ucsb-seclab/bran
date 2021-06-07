import os
from datetime import datetime
from pydriller.domain.commit import Commit, Modification
from pydriller import RepositoryMining, GitRepository
import pickle
import sys

training_set_end = datetime(2015, 12, 31, 23, 59, 59)
test_set_end = datetime(2018, 12, 31, 23, 59, 59)

# -> [(path, funcname, commit, commit_date, author), (n_add, n_del)]
def parse_func_change_from_commit(commit: Commit):
    def parse_func_change_from_modification(modification: Modification):
        if modification.new_path is None: return []
        new_methods = modification.methods
        old_methods = modification.methods_before
        changed_methods = modification.changed_methods
        added = modification.diff_parsed["added"]
        deleted = modification.diff_parsed["deleted"]

        per_func_change = []
        for meth in changed_methods:
            n_add = 0
            n_del = 0
            is_in = False
            if meth in new_methods:
                n_add = sum([1 for x in added if meth.start_line <= x[0] <= meth.end_line])
                is_in = True
            if meth in old_methods:
                n_del = sum([1 for x in deleted if meth.start_line <= x[0] <= meth.end_line])
                is_in = True
            assert(is_in)
            assert(n_add + n_del > 0)
            per_func_change.append(((modification.new_path, meth.name, commit.hash, commit.committer_date, commit.author), (n_add, n_del)))

        return per_func_change

    func_change_stats = [(k, v) for mod in commit.modifications for k, v in parse_func_change_from_modification(mod)]
    return func_change_stats


if __name__ == "__main__":
    # python main.py FFmpeg 2011
    # repo_name = "FFmpeg"
    # year = 2003
    repo_name = sys.argv[1]
    year = int(sys.argv[2])
    save_dir = "../gen_data/"
    repos_dir = "../data/"

    if year == 2000: from_date = datetime(1998, 12, 31, 23, 59, 59)
    else: from_date = datetime(year-1, 12, 31, 23, 59, 59)
    to_date = datetime(year, 12, 31, 23, 59, 59)

    repo_path = os.path.join(repos_dir, repo_name)

    repo = RepositoryMining(repo_path, since=from_date, to=to_date, only_no_merge=True, only_modifications_with_file_types=['.c'])

    recs = []
    commits = list(repo.traverse_commits())
    n_commits = len(commits)
    for i, commit in enumerate(commits):
        print(f"{repo_name}-{year}: {i}/{n_commits}")
        recs.append(parse_func_change_from_commit(commit))

    with open(os.path.join(save_dir, f"{repo_name}_{year}.pkl"), "wb") as f:
        pickle.dump(recs, f)

