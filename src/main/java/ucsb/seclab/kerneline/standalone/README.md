Kerneline Container-based Distributed Deployment
==================

This folder contains 3 runnable classes which can be used to orchestrate a distributed deployment of Kerneline made up of containers. The idea is that the three jar files which can be obtained by compiling this classes can be then deployed in corresponding containers and can be replicated so to reduce the overall runtime needed to create a dataset.

In order to obtain the three jars, for each of the three classes one needs to go through the following steps:

* in pom.xml, set the <main.class> tag to the fully qualified name of the current class (for instance, <main.class>ucsb.seclab.kerneline.standalone.VulnFunctionExtractor</main.class>)
* run mvn clean package to obtain the executable jar file

In the following we detail the requirements for each class, as well as the execution workflow to be followed.

### VulnFunctionExtractor

This class performs the extraction of vulnerable functions starting from the CVEs reported for the codebase being analyzed. The class takes the following input arguments:

* args[0] = index of this parallel instance. If running n pods, each of them should be assigned with an unique index which goes from 0 to n-1
* args[1] = path to a copy of the codebase to be analyzed that is ***dedicated*** to this pod. The assumption is that each pod will see a dedicated file system on which the codebase has been downloaded
* args[2] = path to result folder on which the pod will write its output. This could be shared across the pods since by design they should not conflict on writing to this folder. Currently this folder needs to contain a subfolder named "word2ved-corpus"
* args[3] = list of folders (separated by ":") to be considered for the extraction of functions (for example if linux is the codebase to be analyzed, this argument could be "kernel:mm:fs:net:security:drivers")
* args[4] to args[n] = in order to parallelize the extraction of the vulnerable functions from the CVEs reported for the codebase, the set of CVEs need to be partitioned ahead among the available instances of the pod. Each instance of the pod need to be given as input with a set of arguments pointing to the assigned CVEs. This is the purpose of args[4] to args[n]. Each of these arguments is expected to be formatted in the form <CVE_ID>":"<COMMIT_PATH_SHA> (i.e. the commit fixing a CVE is also expected to be given as input. One can run `/src/main/java/ucsb/seclab/kerneline/sources/CVEs.java` to get the list of CVEs with the corresponding fixing commits for each pod.)

This pod also needs git and indent to be available in the environment at runtime.

### VulnFunctionCharacterizer

This class performs the characterization of vulnerable functions starting from the output of the previous one. Indeed, this should be executed only after VulnFunctionExtractor has been executed. Before executing this class one should go through the following steps:

* Run joern against the result folder that has been populated by VulnFunctionExtractor. 
* Copy the joern generated database to the /data/database folder of the Neo4J installation
* Run Neo4J

We assume Neo4J to run on some dedicated host and all the results of VulnFunctionExtractor to be under the same folder, but it may be also local to the pod if the results from running VulnFunctionExtractor are not gathered all together. The most recent version of Neo4J which is compatible with the database produced by joern is 3.2.12. Neo4J should also needs the following configurations:

* format migration enabled (dbms.allow_format_migration=true)
* bolt connector enabled (dbms.connector.bolt.enabled=true)
* authentication disabled -- just for simplicity (dbms.security.auth_enabled=false)

After this  initial setup, the class can be executed. It takes as input the following arguments:

* args[0] = index of this parallel instance. If running n pods, each of them should be assigned with an unique index which goes from 0 to n-1
* args[1] = path to a copy of the codebase to be analyzed that is ***dedicated*** to this pod. The assumption is that each pod will see a dedicated file system on which the codebase has been downloaded
* args[2] = path to result folder on which the pod will write its output. This could be shared across the pods since by design they should not conflict on writing to this folder. Currently this folder needs to contain a subfolder named "word2ved-corpus"
* args[3] =  nCoChangingThreshold (just a config parameter relevant to the function characterization)
* args[4] = the name of the github repo from where the codebase to be analyzed was cloned (e.g. torvalds/linux)
* args[5] = ip of the Neo4J instance containing the database built from the extracted vulnerable functions at the end of the first step
* args[6] = port of the Neo4J instance containing the database built from the extracted vulnerable functions at the end of the first step

Additionally, this class also needs git and pmccabe (sudo apt-get install pmccabe) to be available in the environment at runtime.

### NonVulnFunctionProcessor

This class is responsible to creating the dataset of non vulnerable function for Kerneline. Before executing pods with this class, one should go through the following steps:

* checkout last commit in period on the codebase to be analyzed
* run joern against the subfolders to be considered at the checked out commit (e.g. in the case of linux: joern kernel drivers mm)
* move the generated database to the /data/database folder of the Neo4J installation
* start Neo4J (wait for migration to finish)

Also in this case Neo4J should be configured as in the previous case:

* format migration enabled (dbms.allow_format_migration=true)
* bolt connector enabled (dbms.connector.bolt.enabled=true)
* authentication disabled -- just for simplicity (dbms.security.auth_enabled=false)

After this  initial setup, the class can be executed. It takes as input the following arguments:

* args[0] = index of this parallel instance. If running n pods, each of them should be assigned with an unique index which goes from 0 to n-1
* args[1] = path to a copy of the codebase to be analyzed that is ***dedicated*** to this pod. The assumption is that each pod will see a dedicated file system on which the codebase has been downloaded
* args[2] = path to result folder on which the pod will write its output. This could be shared across the pods since by design they should not conflict on writing to this folder. Currently this folder needs to contain a subfolder named "word2ved-corpus"
* args[3] =  nCoChangingThreshold (just a integer config parameter relevant to the function characterization, right now just use the magic number 2)
* args[4] = commit to be considered for getting the non vulnerable functions (we assume to be the last in the considered period)
* args[5] = the name of the github repo from where the codebase to be analyzed was cloned (e.g. torvalds/linux)
* args[6] = ip of the Neo4J instance containing the database built from the extracted vulnerable functions at the end of the first step
* args[7] = port of the Neo4J instance containing the database built from the extracted vulnerable functions at the end of the first step
* args[8] = number of functions to be extracted (to limit the runtime, otherwise all the functions in the neo4j database are considered (pass 0 if you want this to actually happen)

Additionally, this class also needs git, indent and pmccabe (sudo apt-get install pmccabe) to be available in the environment at runtime.

In order to simplify the extraction of the commit id to be used to the creation of the non vulnerable functions dataset (which may take same time on codebases with huge histories), here is a list of the last commit for each year in the case of Linux, which we are currently analyzing:

* 2006,669df1b
* 2007,8d2e24c
* 2008,59e315b
* 2009,74e7bb7
* 2010,622d814
* 2011,c7f46b7
* 2012,56431cd
* 2013,90327e7
* 2014,702f7e3
* 2015,8d4ea29
* 2016,ab51e6b
* 2017 6ea0acf

For example, if all the CVEs from 2006 to 2008 have been given as input to the VulnFunctionExtractor pods, then we assume args[4] to be equal to 59e315b for the NonVulnFunctionProcessor pods. 
