# Bran

Related materials for "Bran: Reduce Vulnerability Search Space in Large Open Source Repositories by Learning Bug Symptoms", at AsiaCCS 2021.

Please find the dataset with extracted features under `stats/gen_data`. For each of the four projects we studied, we provide data of normal functions and vulnerable functions of two periods of time(before 2015 and from 2016 to 2018). We further cleaned the dataset so the numbers are slightly different from the paper. A reference random forest model implementation using the data can be found in `stats/src/rf.py`.

The data collection and cleaning setup can be found under `src` and `stats/src`. A description of how most of this part work can be found in `src/main/java/ucsb/seclab/kerneline/standalone/README.md`. We list them here mainly as a reference. Fuzzing-related materials can be found under `fuzzer_stuff`.

Also, just a side note, the project started with the name `kerneline` so you may find it here and there.

Please contact dmeng at ucsb dot edu if you have questions regarding the repository.

