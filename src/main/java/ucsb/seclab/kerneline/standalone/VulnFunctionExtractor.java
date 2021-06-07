package ucsb.seclab.kerneline.standalone;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public class VulnFunctionExtractor {

	private final static Logger logger = LoggerFactory.getLogger(VulnFunctionExtractor.class);

	/*
	 * args[0] = index of this parallel instance
	 */
	/*
	 * args[1] = path to codebase (just a config parameter; I guess the codebase
	 * should be local to the pod and git should be available on the pod)
	 */
	/*
	 * args[2] = path to result folder (it is assumed to be remote but accessible
	 * and writable from the pod that will run this class)
	 */
	/*
	 * args[3] = list of folders (separated by ":") to be considered for the
	 * extraction of functions (just a config parameters)
	 */
	/*
	 * args[4] to args[n] = list of CVEs per commit (in the form of cveId:commitId)
	 * to be processed (this could come from a first processing step ran by the
	 * master on the master machine -- TO CHECK)
	 */
	public static void main(String[] args) throws JsonParseException, JsonMappingException, IOException {

		// will be written to an output json  on the master
		List<String> outputJsonNodes = new ArrayList<String>();
		
		// will be writte to an output json file that need to be accessed as input by the second step of the  pipeline
		List<Function> vulnerableFunctions = new ArrayList<Function>();
	
		Map<String, String> commitsPerCves = new HashMap<String, String>();

		Integer instanceIdx = 1;
		String localCodebase = args[0];
		String outputDir = args[1];
		List<String> subfolders = null;

		Integer index = 2;

		while (index < args.length) {
			commitsPerCves.put(args[index].split(":")[0], args[index].split(":")[1]);
			index = index + 1;
		}

		ObjectMapper mapper = new ObjectMapper();
		ArrayNode dataset = mapper.createArrayNode();
		String commitId = "";
		Set<String> affectedFunctionsNames = null;
		List<String> affectedFiles = null;
		String[] functionBodies = new String[2];

		ArrayNode affectedFunctionsJsonArray = null;
		ObjectNode functionEntry = null;
		ObjectNode cveEntry;
		ArrayNode affectedFilesJsonArray = null;
		ArrayNode affectedFunctionsNamesJsonArray = null;
		Function tmpFun = null;
		
		for (String cve : commitsPerCves.keySet()) {


			// create new json dataset entry for current CVE
			cveEntry = mapper.createObjectNode();
			affectedFilesJsonArray = mapper.createArrayNode();
			affectedFunctionsJsonArray = mapper.createArrayNode();
			affectedFunctionsNamesJsonArray = mapper.createArrayNode();
			cveEntry.put("cveId", cve);
			cveEntry.put("patch_commit_id", commitId);

			// get the commit id that was fixing the current CVE
			commitId = commitsPerCves.get(cve);

			logger.info("Processing: " + cve + ", commit: " + commitId);

			// extract files affected by the commit (performs git checkout!)
			affectedFiles = Utils.extractCommitAffectedFiles(commitId, localCodebase, outputDir + "/" + cve,
					subfolders);
			logger.info("Number of file (in the considered subfolders) affected by commit " + commitId + ": "
					+ affectedFiles.size());

			// extract names of the functions that were affected by the commit
			affectedFunctionsNames = Utils.extractAffectedFunctionsNames(
					outputDir + "/" + cve + "/" + commitId, affectedFiles);
			logger.info("Number of functions  (in the considered subfolders) affected by commit " + commitId + ": "
					+ affectedFunctionsNames.size());

			// extract the functions that were affected by the commit and insert all the
			// extracted functions in the current CVE dataset entry

			for (String functionName : affectedFunctionsNames) {
				tmpFun = new Function();
				tmpFun.setName(functionName);
				tmpFun.setFixingCommit(commitId);
				tmpFun.setFixingCve(cve);
				tmpFun.setId(tmpFun.getName() + "_" + tmpFun.getFileRelative() + "_" + commitId + "_" + cve);
				tmpFun.setSha(DigestUtils.sha256Hex(commitId + functionName));
				tmpFun.setIsVulnerable(true);
				affectedFunctionsNamesJsonArray.add(functionName);

				logger.info("Extracting body of function " + tmpFun.getName() + " at commit " + commitId);
				functionBodies = Utils.extractVulnerableFunctionBody(outputDir, cve, commitId, tmpFun);

				if (functionBodies[0] != null && tmpFun.getFile().endsWith(".c")) {

					tmpFun.setBody(functionBodies[0]);
					
					vulnerableFunctions.add(tmpFun);
					functionEntry = mapper.createObjectNode();
					functionEntry.put(functionName, functionBodies[0]);
					affectedFunctionsJsonArray.add(functionEntry);
				}

			}

			logger.info("Number of functions (in the considered subfolders) affected by commit " + commitId + ": "
					+ affectedFunctionsNames.size());

			for (String file : affectedFiles) {
				affectedFilesJsonArray.add(file);
			}
			cveEntry.put("affectedFiles", affectedFilesJsonArray);

			cveEntry.put("affectedFunctionsNames", affectedFunctionsNamesJsonArray);

			cveEntry.put("affectedFunctionsInSubfolder", affectedFunctionsJsonArray);

			// add entry for the current CVE to the output dataset
			outputJsonNodes.add(cveEntry.toString());
			
		}
		
		// write output json file
		
		for (int i = 0; i < outputJsonNodes.size(); i++) {
			dataset.add(mapper.readValue(outputJsonNodes.get(i), ObjectNode.class));
		}

		try {
			Utils.writeFile(outputDir + "/kerneline-dataset" + instanceIdx + ".json", dataset.toString());
		} catch (IOException e) {
			logger.error("Error writing the output Json dataset.");
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
		
		// write output functions for next step
		mapper.writeValue(new File(outputDir + "/vulnFuns" + instanceIdx + ".json"), vulnerableFunctions);
		
		for (File f : findDirectoriesWithSameName("new_files", new File(outputDir))) {
			String[] entries = f.list();
			for (String s : entries) {
				File currentFile = new File(f.getPath(), s);
				currentFile.delete();
			}
			f.delete();
		}
	}
	
	private static List<File> findDirectoriesWithSameName(String name, File root) {
		List<File> result = new ArrayList<>();

		for (File file : root.listFiles()) {
			if (file.isDirectory()) {
				if (file.getName().equals(name)) {
					result.add(file);
				}

				result.addAll(findDirectoriesWithSameName(name, file));
			}
		}

		return result;
	}

}
