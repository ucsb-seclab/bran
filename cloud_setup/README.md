# Running the cloud setup
______
This has 2 components: `master` and `pods`
# Running `VulFunctionExtractor` master
Edit the file: `vul_func_extra_master.py`, by changing the variables `OUTPUT_SUCCESS_FOLDER` and `OUTPUT_ERROR_FOLDER` to folders where output of successfully and errored requests respectively.

Running the master:

```
cd cloud_setup
python vul_func_extra_master.py <file_containing_cve_list>
```
Example of cve list file:
```
CVE-2006-6333:ee28b0da1069ced1688aa9d0b7b378353b988321
CVE-2006-2071:b78b6af66a5fbaf17d7e6bfc32384df5e34408c8
CVE-2008-2826:735ce972fbc8a65fb17788debd7bbe7b4383cc62
CVE-2008-4445:d97240552cd98c4b07322f30f66fd9c3ba4171de
CVE-2008-4395:49945b423c2f7e33b4c579ca460df6a806ee8f9f
CVE-2007-4311:faa3369ac2ea7feb0dd266b6a5e8d6ab153cf925
```

Make a note of the IP address on which master is running.
Lets call it `MASTER_IP`.
### Change the IP in the docker file
Change the ip address in the file: `cloud_setup/VulnFunctionExtractor/docker/Dockerfile` to the master IP.

i.e.,
```
CMD bash -c "cd /data/scripts; python vul_func_extra_client.py http://<MASTER_IP>:8080"
```

### Building the docker image
```
cd cloud_setup
./build.sh VulnFunctionExtractor
```

### Scheduling the pods
Change the yaml file: `cloud_setup/yamls/vul_func_extractor.yaml`, to change the `imagePullSecrets` to your secret name i.e., `<gitlabusername>gitsec`

Scheduling the pods:
```
cd cloud_setup
kubectl create -f vul_func_extractor.yaml
```

# Running `VulnFunctionCharacterizer` master
Edit the file: `vul_func_charect_master.py`, by changing the variables `OUTPUT_SUCCESS_FOLDER`, `OUTPUT_ERROR_FOLDER`, `NEOIP`, `NEOPORT`, `CHANGETHRESH`, and `GITREPONAME` to folders where output of successfully and errored requests respectively.

Running the master:

```
cd cloud_setup
python vul_func_charect_master.py <success_output_folder_of_vul_extractor_master>
```

Make a note of the IP address on which master is running.
Lets call it `MASTER_IP`.
### Change the IP in the docker file
Change the ip address in the file: `cloud_setup/VulnFunctionCharacterizer/docker/Dockerfile` to the master IP.

i.e.,
```
CMD bash -c "cd /data/scripts; python vul_func_charect_client.py http://<MASTER_IP>:8080"
```

### Building the docker image
```
cd cloud_setup
./build.sh VulnFunctionCharacterizer
```

### Scheduling the pods
Change the yaml file: `cloud_setup/yamls/vul_func_charecterizer.yaml`, to change the `imagePullSecrets` to your secret name i.e., `<gitlabusername>gitsec`

Scheduling the pods:
```
cd cloud_setup
kubectl create -f vul_func_charecterizer.yaml
```