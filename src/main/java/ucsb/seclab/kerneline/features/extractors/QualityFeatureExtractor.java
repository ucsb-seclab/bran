package ucsb.seclab.kerneline.features.extractors;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.math.NumberUtils;
import org.apache.flink.shaded.curator.org.apache.curator.shaded.com.google.common.io.Files;
import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public abstract class QualityFeatureExtractor {

	protected String pathToCodebase;

	protected String pathToResultFolder;

	private static final Logger logger = LoggerFactory.getLogger(QualityFeatureExtractor.class);

	public QualityFeatureExtractor() {

	}

	public QualityFeatureExtractor(String pathToCodebase, String pathToResultFolder) {
		this.pathToCodebase = pathToCodebase;
		this.pathToResultFolder = pathToResultFolder;
	}

	public Integer getLoc(String function) {
		return function.split("\n").length;
	}

	public Integer getNumberOfInputParameters(Function f) {
		return JoernNeo4JDriver.getInstance().getInputParameters(f, this.pathToResultFolder).size();
	}

	public Integer getNumberOfDeclaredVars(Function f) {
		return JoernNeo4JDriver.getInstance().getDeclaredVarsIds(f, this.pathToResultFolder).size();
	}

	public Integer getNumberOfCoLocatedFunctions(Function f) {
		return JoernNeo4JDriver.getInstance().getCoLocatedFunctions(f, this.pathToResultFolder).size();
	}

	public Integer getNumberOfCastExpressions(Function f) {
		return JoernNeo4JDriver.getInstance().getNumCastExpressions(f, this.pathToResultFolder).size();
	}

	public Double getMcCabeComplexity(String function) throws IOException, InterruptedException {
		File tempCode = File.createTempFile("function", null);
		String functionPath = tempCode.getAbsolutePath();
		File tempScript = File.createTempFile("script", null);

		Writer streamWriter;
		streamWriter = new OutputStreamWriter(new FileOutputStream(tempCode));

		PrintWriter printWriter = new PrintWriter(streamWriter);

		printWriter.println(function);

		printWriter.close();

		streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

		printWriter = new PrintWriter(streamWriter);

		printWriter.println("#!/bin/bash");
		printWriter.println("pmccabe " + functionPath);

		printWriter.close();

		ProcessBuilder pb = new ProcessBuilder("bash", tempScript.toString());
		// pb.inheritIO();
		Process process = pb.start();
		// process.waitFor();

		BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		String line = null;
		String previous = null;
		while ((line = reader.readLine()) != null) {
			previous = line;
		}

		tempScript.delete();
		tempCode.delete();

		// getting the traditional (no the modified!) McCabe complexity

		if (previous != null && previous.split("	").length > 1 && NumberUtils.isNumber(previous.split("	")[1])) {
			return Double.parseDouble(previous.split("	")[1]);
		} else {
			return null;
		}
	}

	public Integer getModuleNumChanges(Function f) throws ParseException {
		// git log --oneline -- $file | wc -l
		String script = "cd " + this.pathToCodebase + "\n" + "git --no-pager log --oneline -- $1 | wc -l";
		List<String> args = new ArrayList<String>();
		args.add(f.getFileRelative());
		String result = Utils.executeBashScript(script, args);
		return NumberFormat.getInstance().parse(result).intValue();
	}

	public Integer getModuleNumAuthors(Function f) throws ParseException {
		// git log -- $file | grep 'Author: ' | grep -E -o
		// "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort | uniq | wc -l
		String script = "cd " + this.pathToCodebase + "\n"
				+ "git --no-pager log -- $1 | grep 'Author: ' | grep -E -o  \"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}\\b\" | sort | uniq | wc -l";
		List<String> args = new ArrayList<String>();
		args.add(f.getFileRelative());
		String result = Utils.executeBashScript(script, args);
		return NumberFormat.getInstance().parse(result).intValue();
	}

	public Set<String> getCommitsModifyingFunction(Function f) {
		String script = "git --no-pager log -L :$1:$2 -- $2 | egrep '[0-9a-f]{40}' -o";
		List<String> args = new ArrayList<String>();
		args.add(f.getName());
		args.add(f.getFileRelative());
		return new HashSet<String>(
				Arrays.asList(Utils.executeBashScriptFromLocation(this.pathToCodebase, script, args).split("\n")));
	}

	public Double getCoChangingFunctionsTotalComplexity(Function f, Integer threshold, Set<String> commits) {

		for (String c : commits) {
			logger.info(c);
		}

		// for each commit get the names of all the functions that were modified
		Map<String, Set<String>> modifiedFunctionsPerCommit = new HashMap<String, Set<String>>();
		for (String commit : commits) {
			if (Utils.isValidCommit(this.pathToCodebase, commit)) {
				File tempDir = Files.createTempDir();
				List<String> affectedFiles = Utils.extractCommitAffectedFiles(commit, this.pathToCodebase,
						tempDir.getAbsolutePath(), null);
				modifiedFunctionsPerCommit.put(commit,
						Utils.extractAffectedFunctionsNames(tempDir.getAbsolutePath() + "/" + commit, affectedFiles));
				tempDir.delete();
			}
		}

		// count the number of changes per function
		Map<String, Integer> nChangesPerFunction = new HashMap<String, Integer>();

		for (String commit : modifiedFunctionsPerCommit.keySet()) {
			for (String function : modifiedFunctionsPerCommit.get(commit)) {
				if (nChangesPerFunction.containsKey(function)) {
					nChangesPerFunction.put(function, nChangesPerFunction.get(function) + 1);
				} else {
					nChangesPerFunction.put(function, 1);
				}
			}
		}

		// take the functions that were more often modified together with f (those
		// having the higher change counts)
		logger.info("Extracting the functions that were more often modified (threshold = " + threshold + ")");
		Double totalComplexity = 0.0;
		String tmpFunctionBody = null;
		List<String> modifiedFiles = null;
		String lastChangingCommit = null;

		for (String function : nChangesPerFunction.keySet()) {
			if (nChangesPerFunction.get(function) >= threshold) {

				logger.info("Extracting function: " + function + " modified " + nChangesPerFunction.get(function)
						+ " times.");

				lastChangingCommit = this.getLastChangingCommit(modifiedFunctionsPerCommit, function);
				logger.info("Checking out last commit in which the function was modified: " + lastChangingCommit);

				Utils.executeBashScriptFromLocation(this.pathToCodebase, "git checkout " + lastChangingCommit,
						new ArrayList<String>());

				logger.info("Getting file modified by commit.");
				modifiedFiles = Utils.getAffectedFilesNames(lastChangingCommit, pathToCodebase);

				Iterator<String> iter = modifiedFiles.iterator();
				String nextFile = null;
				while (iter.hasNext() && tmpFunctionBody == null) {
					nextFile = iter.next();
					tmpFunctionBody = Utils.extractFunctionBodyFromFile(pathToCodebase + "/" + nextFile, function);
				}

				if (tmpFunctionBody != null) {
					try {
						totalComplexity = totalComplexity + this.getMcCabeComplexity(tmpFunctionBody);
					} catch (IOException | InterruptedException e) {
						throw new RuntimeException("Error computing the McCabe complexity.");
					} catch (NullPointerException e) {
						return null;
					}
				} else {
					logger.debug("FOUND FUNCTION WITH NULL BODY!");
				}

			}
		}

		logger.info("Total complexity: " + totalComplexity);

		// return the total complexity

		return totalComplexity;
	}

	public Integer getCoChangingFunctionsTotalLoc(Function f, Integer threshold, Set<String> commits) {

		for (String c : commits) {
			logger.info(c);
		}

		// for each commit get the names of all the functions that were modified
		Map<String, Set<String>> modifiedFunctionsPerCommit = new HashMap<String, Set<String>>();
		for (String commit : commits) {
			if (Utils.isValidCommit(this.pathToCodebase, commit)) {
				File tempDir = Files.createTempDir();
				List<String> affectedFiles = Utils.extractCommitAffectedFiles(commit, this.pathToCodebase,
						tempDir.getAbsolutePath(), null);
				modifiedFunctionsPerCommit.put(commit,
						Utils.extractAffectedFunctionsNames(this.pathToCodebase + "/" + commit, affectedFiles));
				tempDir.delete();
			}
		}

		// count the number of changes per function
		Map<String, Integer> nChangesPerFunction = new HashMap<String, Integer>();

		for (String commit : modifiedFunctionsPerCommit.keySet()) {
			for (String function : modifiedFunctionsPerCommit.get(commit)) {
				if (nChangesPerFunction.containsKey(function)) {
					nChangesPerFunction.put(function, nChangesPerFunction.get(function) + 1);
				} else {
					nChangesPerFunction.put(function, 1);
				}
			}
		}

		// take the functions that were more often modified together with f (those
		// having the higher change counts)
		// for each such function extract the body and computer its complexity
		// sums up all the complexities
		logger.info("Extracting the functions that were more often modified (threshold = " + threshold);
		Integer totalLoc = 0;
		String tmpFunctionBody = null;
		List<String> modifiedFiles = null;
		String lastChangingCommit = null;

		for (String function : nChangesPerFunction.keySet()) {
			if (nChangesPerFunction.get(function) >= threshold) {

				logger.info("Extracting function: " + function + " modified " + nChangesPerFunction.get(function)
						+ " times.");

				lastChangingCommit = this.getLastChangingCommit(modifiedFunctionsPerCommit, function);
				logger.info("Checking out last commit in which the function was modified: " + lastChangingCommit);

				Utils.executeBashScriptFromLocation(this.pathToCodebase, "git checkout " + lastChangingCommit,
						new ArrayList<String>());

				logger.info("Getting file modified by commit.");
				modifiedFiles = Utils.getAffectedFilesNames(lastChangingCommit, pathToCodebase);

				Iterator<String> iter = modifiedFiles.iterator();

				while (iter.hasNext() && tmpFunctionBody == null) {
					tmpFunctionBody = Utils.extractFunctionBodyFromFile(pathToCodebase + "/" + iter.next(), function);
				}

				if (tmpFunctionBody != null) {
					totalLoc = totalLoc + this.getLoc(tmpFunctionBody);
				} else {
					logger.debug("FOUND FUNCTION WITH NULL BODY!");
				}

			}
		}

		logger.info("Total loc: " + totalLoc);

		// return the total loc

		return totalLoc;
	}

	protected String getLastChangingCommit(Map<String, Set<String>> modifiedPerCommit, String fun) {
		for (String commit : modifiedPerCommit.keySet()) {
			for (String l : modifiedPerCommit.get(commit)) {
				if (l.equals(fun)) {
					return commit;
				}
			}
		}

		return null;
	}

	private enum ScanCommentsState {
		TEXT, SAW_SLASH, SAW_STAR, SINGLE_COMMENT, MULTI_COMMENT
	}

	public Integer countCommentedLines(String code) {
		Integer count = 0;
		Integer multi = 0;
		Integer single = 0;
		int i = 0;
		char c;
		ScanCommentsState state = ScanCommentsState.TEXT;

		while (i < code.length()) {
			c = code.charAt(i);
			switch (state) {
			case TEXT: {
				switch (c) {
				case '/':
					state = ScanCommentsState.SAW_SLASH;
					break;
				case '\n':
					count = count + 1; // fall through
				default:
					break;
				}
			}
				break;
			case SAW_SLASH: {
				switch (c) {
				case '/':
					state = ScanCommentsState.SINGLE_COMMENT;
					break;
				case '*':
					state = ScanCommentsState.MULTI_COMMENT;
					break;
				case '\n':
					count = count + 1; // fall through
				default:
					state = ScanCommentsState.TEXT;
					break;
				}
			}
				break;
			case SAW_STAR: {
				switch (c) {
				case '/':
					state = ScanCommentsState.TEXT;
					multi = multi + 1;
					break;
				case '*':
					break;
				case '\n':
					count = count + 1;
					multi = multi + 1;// fall through
				default:
					state = ScanCommentsState.MULTI_COMMENT;
					break;
				}
			}
				break;
			case SINGLE_COMMENT: {
				switch (c) {
				case '\n':
					state = ScanCommentsState.TEXT;
					single = single + 1;
					count = count + 1; // fall through
				default:
					break;
				}
			}
				break;
			case MULTI_COMMENT: {
				switch (c) {
				case '*':
					state = ScanCommentsState.SAW_STAR;
					break;
				case '\n':
					count = count + 1;
					multi = multi + 1;// fall through
				default:
					break;
				}
			}
				break;
			default: // not reachable
				break;
			}
			i = i + 1;
		}

		return single + multi;
	}

	public Integer getNumberOfNullPtrAccess(Function f) {
		return JoernNeo4JDriver.getInstance().getNumNullPtrAccess(f, this.pathToResultFolder);
	}

	public Integer getNumberOfPtrModification(Function f) {
		return JoernNeo4JDriver.getInstance().getNumPtrModification(f, this.pathToResultFolder);
	}

	public Integer getNumberOfSanityChecksOnParameters(Function f) {
		JoernNeo4JDriver neo4j = JoernNeo4JDriver.getInstance();

		List<Value> parameters = neo4j.getInputParameters(f, this.pathToResultFolder);
		List<Value> ids = neo4j.getAllIdsInConditions(f, this.pathToResultFolder);

		Integer cont = 0;

		for (Value p : parameters) {
			String[] parameterSplits = p.get("code").toString().replaceAll("\"", "").split(" ");
			String parameterName = parameterSplits[parameterSplits.length - 1].replaceAll("\\*", "");
			for (Value id : ids) {
				if (id.get("code").toString().replaceAll("\"", "").equals(parameterName)) {
					cont = cont + 1;
				}
			}
		}

		return cont;

	}
}
