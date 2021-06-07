package ucsb.seclab.kerneline.flink.pipelines;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.apache.flink.api.common.functions.RichFlatMapFunction;
import org.apache.flink.api.common.functions.RichMapFunction;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.model.Revision;
import ucsb.seclab.kerneline.sources.NVD;
import ucsb.seclab.kerneline.utils.Utils;
import ucsb.seclab.kerneline.model.CVEHistory;

/* 
 * Each input tuple is a CVEHistory object in which fixingRevision and breakingRevision have been set.
 * This class extract and adds to the CVEHistory object the bodies and ASTs of all the functions
 * affected by breakingRevision over the entire history up to fixinngRevision. This process
 * extracts, for each affected functions, a set of vulnerable versions of the functions and a single
 * fixed version, where a version is characterized by the function body and its AST at a specific commit.
 */
public class ExtractCVEHistory extends RichFlatMapFunction<CVEHistory, CVEHistory> {

	private static final long serialVersionUID = -1416144117691298218L;

	private final Logger logger = LoggerFactory.getLogger(ExtractCVEHistory.class);

	private String outputDir;
	private String localCodebase;
	private List<String> subfolders;
	private Integer nCoresPerHost;
	private List<CVEHistory> cves;

	public ExtractCVEHistory(Map<String, Object> config) {
		this.outputDir = (String) config.get("outputDir");
		this.localCodebase = ((String) config.get("localCodebase"));
		this.subfolders = (List<String>) config.get("subfolders");
		this.nCoresPerHost = (Integer) config.get("nCoresPerHost");
		this.cves = new ArrayList<CVEHistory>();
	}

	@Override
	public void open(Configuration config) {
		this.localCodebase = this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost;
	}

	@Override
	public void close() throws JsonGenerationException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(new File(outputDir + "/cveHistories"
				+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"), this.cves);
		Utils.executeBashScriptFromLocation(this.localCodebase, "git checkout master", new ArrayList<String>());
	}

	@Override
	public void flatMap(CVEHistory cve, Collector<CVEHistory> out) throws Exception {

		// extract the functions modified by fixingRevision (bodies and ASTs) and
		// update the fixing revision of the cve object
		logger.info("Extracting functons modified by fixing revision " + cve.getFixingRevision().getCommit());
		cve.setFixingRevisionFunctions(
				this.extractCommitAffectedFunctions(cve.getFixingRevision().getCommit(), cve.getCveId()));

		logger.info("Extracting functons modified by breaking revision : " + cve.getBreakingRevision().getCommit());
		if(!cve.getBreakingRevision().getCommit().equals("1da177e4c3f41524e886b7f1b8a0c1fc7321cac2")) {
			// if the breaking commit is not the first commit in the history
			// then we can checkout that commit, see which functions were modified
			// and consider only those as the set of functions which introduced the vulnerability
			
			// extract the functions modified by breakingRevision (bodies and ASTs) and
			// update the breaking revision of the cve object
			cve.setBreakingRevisionFunctions(
					this.extractCommitAffectedFunctions(cve.getBreakingRevision().getCommit(), cve.getCveId()));		
		} else {
			// if the breaking commit is the first commit in the history, 
			// we need to extract from the initial commit
			// all the functions that were then fixed at the fixing commit
			// as the most conservative guess that we can make is that all such functions were modified 
			// when the vulnerability was introduced
			
			// extract the functions modified by fixingRevision (bodies and ASTs) but at the initial commit and
			// update the breaking revision of the cve object
			logger.info("Breaking revision is the first of the history. Extracting from it all the functions modified by the **fixing** revision (conservative assumption).");
			cve.setBreakingRevisionFunctions(
					this.extractFunctionsAtCommit(cve.getFixingRevision().getAffectedFunctions(), cve.getBreakingRevision().getCommit(), cve.getCveId()));			
		}

		// for each extracted function, extract all the commits at which is was modified
		// up to fixingRevision
		
		Set<String> intermediateRevisions = new HashSet<String>();
		
		for(Function f: cve.getBreakingRevision().getAffectedFunctions()) {
			intermediateRevisions.addAll(this.getCommitsModifyingFunction(f, cve.getBreakingRevision().getCommit(), cve.getFixingRevision().getCommit()));
		}		

		// for each extract commit, extract the functions modified by the commit (bodies
		// and ASTs) and add a new Revision object to the cve object
		Revision current = null;
		
		for(String commit: intermediateRevisions) {
			current = new Revision();
			current.setCommit(commit);
			current.setAffectedFunctions(this.extractCommitAffectedFunctions(commit, cve.getCveId()));
			cve.setNonFixingChange(current);
		}
		
		// output the cve objext

		this.cves.add(cve);
	}

	private List<Function> extractCommitAffectedFunctions(String commitId, String cve) {

		List<Function> vulnerableFunctions = new ArrayList<Function>();

		Set<String> affectedFunctionsNames = null;
		List<String> affectedFiles = null;
		String functionBody = null;
		Function tmpFun = null;

		// extract files affected by the commit (performs git checkout!)
		logger.info("Extracting files affected by commit " + commitId);
		affectedFiles = Utils.extractCommitAffectedFiles(commitId, this.localCodebase, this.outputDir + "/" + cve,
				this.subfolders);
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Number of file (in the considered subfolders) affected by commit " + commitId + ": "
				+ affectedFiles.size());

		// extract names of the functions that were affected by the commit
		logger.info("Extracting names of functions affected by commit " + commitId);
		affectedFunctionsNames = Utils.extractAffectedFunctionsNames(this.outputDir + "/" + cve + "/" + commitId,
				affectedFiles);
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Number of functions (in the considered subfolders) affected by commit " + commitId + ": "
				+ affectedFunctionsNames.size());

		// extract the functions that were affected by the commit and insert all the
		// extracted functions in the current CVE dataset entry

		for (String functionName : affectedFunctionsNames) {
			tmpFun = new Function();
			tmpFun.setName(functionName);

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "]Extracting body of function "
					+ tmpFun.getName() + " at commit " + commitId);
			functionBody = this.extractVulnerableFunctionBody(this.outputDir,
					cve, commitId, tmpFun);

			if (functionBody != null && tmpFun.getFileRelative().endsWith(".c")) {
				logger.info("Got function boy. Adding to list of extracted functions.");
				tmpFun.setId(
						tmpFun.getName() + "_" + tmpFun.getFileRelative().replaceAll("/", "%").replaceAll("\\.c", "")
								+ "_" + commitId + "_" + cve);
				tmpFun.setBody(functionBody);
				vulnerableFunctions.add(tmpFun);
			} else {
				logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
						+ "] Dropping function because of empty extracted body: " + tmpFun.getName() + " "
						+ tmpFun.getFileRelative());
			}

		}

		return vulnerableFunctions;
	}

	public Set<String> getCommitsModifyingFunction(Function f, String start, String end) {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting commits in which "
				+ f.getName() + " was modified.");
		String script = "git --no-pager log -L :$1:$2 -- $2 " + start + ".." + end + " | egrep '[0-9a-f]{40}' -o";
		List<String> args = new ArrayList<String>();
		args.add(f.getName());
		args.add(f.getFileRelative());
		return new HashSet<String>(
				Arrays.asList(Utils.executeBashScriptFromLocation(this.localCodebase, script, args).split("\n")));
	}

	private List<Function> extractFunctionsAtCommit(List<Function> toExtract, String commit, String cve) {
		List<Function> toReturn = new ArrayList<Function>();
		Function tmp = null;

		// checkout commit
		Utils.executeBashScriptFromLocation(this.localCodebase, "git checkout " + commit, new ArrayList<String>());

		// for each function in toExtract try (if the file and the function exist) to
		// extract the function from its file
		for (Function f : toExtract) {
			String body = Utils.extractFunctionBodyFromFile(this.localCodebase + "/" + f.getFileRelative(),
					f.getName());
			tmp = new Function();
			tmp.setName(f.getName());
			tmp.setFileRelative(f.getFileRelative());
			tmp.setId(tmp.getName() + "_" + tmp.getFileRelative().replaceAll("/", "%").replaceAll("\\.c", "") + "_"
					+ commit + "_" + cve);
			tmp.setBody(body);
			toReturn.add(tmp);
		}

		// checkout master
		Utils.executeBashScriptFromLocation(this.localCodebase, "git checkout master", new ArrayList<String>());

		return toReturn;
	}

	public String extractVulnerableFunctionBody(String outputDir, String cve, String commitId, Function function) {
		Process process = null;
		ProcessBuilder pb = null;
		BufferedReader reader = null;
		StringBuilder builder = new StringBuilder();
		String functionLine = null;
		File tempScript = null;
		Writer streamWriter = null;
		PrintWriter printWriter = null;
		String tmpFilePath;

		File newDir = new File(outputDir + "/" + cve + "/" + commitId + "/new_files");

		File[] directoryListing = newDir.listFiles();
		if (directoryListing != null) {
			for (File child : directoryListing) {
				if (!FilenameUtils.getExtension(child.getAbsolutePath()).equals("txt")) {
					try {
						tempScript = File.createTempFile("script", null);

						streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));
						printWriter = new PrintWriter(streamWriter);

						printWriter.println("#!/bin/sh");
						printWriter.println("indent -st -orig \"$1\" | awk '");
						printWriter.println("BEGIN { state = 0; last = \"\"; }");
						printWriter.println("$0 ~ /^'$2'\\(/ { print last; state = 1; }");
						printWriter.println("        { if (state == 1) print; }");
						printWriter.println("$0 ~ /^}/ { if (state) state = 2; }");
						printWriter.println("        { last = $0; }");
						printWriter.println("'");

						printWriter.close();

						pb = new ProcessBuilder("bash", tempScript.toString(), child.getAbsolutePath(),
								function.getName());
						process = pb.start();

						reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
						while ((functionLine = reader.readLine()) != null) {
							builder.append(functionLine);
							builder.append(System.getProperty("line.separator"));
						}

						if (!builder.toString().isEmpty()) {

							tmpFilePath = Utils.executeBashScriptFromLocation(outputDir + "/" + cve + "/" + commitId,
									"grep " + child.getName() + " affected-files.txt", new ArrayList<String>());

							function.setFileRelative(tmpFilePath.substring(0, tmpFilePath.length() - 1));
							return builder.toString();

						}
					} catch (IOException e) {
						throw new RuntimeException(e.getMessage(), e.getCause());
					} finally {
						tempScript.delete();
					}

				}
			}
		}

		return null;
	}

}
