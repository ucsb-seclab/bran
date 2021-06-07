package ucsb.seclab.kerneline.standalone;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.kohsuke.github.GHUser;
import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.features.extractors.NonVulnQualityFeatureExtractor;
import ucsb.seclab.kerneline.github.GithubDriver;
import ucsb.seclab.kerneline.github.UsersCacheMissException;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.FunctionNotFoundException;
import ucsb.seclab.kerneline.utils.Utils;

public class NonVulnFunctionProcessor {

	private static final Logger logger = LoggerFactory.getLogger(NonVulnFunctionProcessor.class);

	private static NonVulnQualityFeatureExtractor qfe;

	private static GithubDriver github;

	/*
	 * args[0] = index of this instance
	 */
	/*
	 * args[1] = path to codebase
	 */
	/*
	 * args[2] = path to result folder (right now it is assumed it contains a
	 * subfolder named "word2vec"
	 */
	/*
	 * args[3] = nCoChangingThreshold (just a config parameter relevant to the
	 * function characterization)
	 */
	/*
	 * args[4] = commit to be considered for getting the non vulnerable functions
	 * (we assume to be the last in the considered period)
	 */
	/*
	 * args[5] = the name of the github repo from where the local codebase was
	 * clones
	 */
	/*
	 * args[6] = ip of the neo4j instance containing the database built from the
	 * extracted vulnerable functions at the end of the first step
	 */
	/*
	 * args[7] = port of the neo4j instance containing the database built from the
	 * extracted vulnerable functions at the end of the first step
	 */
	/*
	 * args[8] = number of functions to be extracted (to limit the runtime,
	 * otherwise all the functions in the neo4j database are considered; pass 0 if
	 * you want this beaviour
	 */

	// OTHER ASSUMPTIONS AND REQUIREMENTS
	/*
	 * neo4j is assumed to be deployed without authentication enabled
	 * (dbms.security.auth_enabled=false) indent is installed on the pod machine git
	 * is installed on the pod machine pmccabe is installed on the pod machine (sudo
	 * apt-get install pmccabe) use neo4j 3.2.12 for joern compatibility neo4j
	 * configured with format migration enabled (dbms.allow_format_migration=true)
	 * neo4j configured with bolt connector enabled
	 * (dbms.connector.bolt.enabled=true)
	 */
	// STEPS TO BE DONE BEFORE RUNNING THE POD
	/*
	 * checkout last commit in period on the codebase to be analyzed run joern
	 * against the subfolders to be considered at the checked out commit move the
	 * generated database to the ./data/database folder of the neo4j installation
	 * start neo4j (wait for migration to finish)
	 */
	public static void main(String[] args) throws FunctionNotFoundException, IOException {
		Process process = null;
		ProcessBuilder pb = null;
		BufferedReader reader = null;
		StringBuilder builder = null;
		String functionLine = null;
		File tempScript = null;
		Writer streamWriter = null;
		PrintWriter printWriter = null;

		Integer instanceIdx = Integer.parseInt(args[0]);
		String localCodebase = args[1];
		String outputDir = args[2];
		Integer nCoChangingThreshold = Integer.parseInt(args[3]);
		String lastCommitInPeriod = args[4];
		String githubRepoName = args[5];
		String neo4jIp = args[6];
		Integer neo4jPort = Integer.parseInt(args[7]);
		Integer nFuns = Integer.parseInt(args[8]);
		String githubUser = args[9];
		String githubPassword = args[10];

		JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();
		joern.init("bolt://" + neo4jIp + ":" + neo4jPort, "", "");
		logger.info("Checking out last commit in considered period.");
		Utils.executeBashScriptFromLocation(localCodebase, "git checkout " + lastCommitInPeriod,
				new ArrayList<String>());

		qfe = new NonVulnQualityFeatureExtractor(localCodebase, outputDir);

		try {
			github = new GithubDriver(githubRepoName, githubUser, githubPassword);
		} catch (IOException e1) {
			logger.error("Problems instantiating Github client.");
			e1.printStackTrace();
		}

		// this should come as input from somewhere and should be read from querying
		// joern on the master node
		ObjectMapper mapper = new ObjectMapper();
		List<Function> functions = mapper.readValue(new File(outputDir + "/vulnFuns" + instanceIdx + ".json"),
				new TypeReference<List<Function>>() {
				});

		for (Function f : functions) {
			f.setIsVulnerable(false);

			try {

				logger.info("Extracting and characterizing function: " + f.getId());
				builder = new StringBuilder();

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

				logger.info("Extracting non vulnerable function " + f.getName() + " from file " + f.getFile());

				pb = new ProcessBuilder("bash", tempScript.toString(), f.getFile(), f.getName());

				process = pb.start();

				// process.waitFor();

				reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
				while ((functionLine = reader.readLine()) != null) {
					builder.append(functionLine);
					builder.append(System.getProperty("line.separator"));
				}

				if (!builder.toString().isEmpty()) {
					f.setSha(DigestUtils.sha256Hex(lastCommitInPeriod + f.getName()));
					f.setId(f.getName() + "_" + f.getFileRelative() + "_" + lastCommitInPeriod);
					f.setFileRelative(f.getFile().replaceAll(localCodebase + "/", ""));
					f.setBody(builder.toString());
					f.setIsVulnerable(false);
					logger.info("Found non vulnerable function with non null body: " + f.getName());
					f = characterizeNonVulnFunction(f, localCodebase, outputDir, nCoChangingThreshold);

					// f should be at this point written to the remote output file for non
					// vulnerable functions (args[4])
				} else {
					logger.info("Found non vulnerable function with null body: " + f.getName());
				}
			} catch (IOException e) {
				throw new RuntimeException(e.getMessage(), e.getCause());
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				tempScript.delete();
			}

		}

		logger.info("Checking out back to head revision.");
		Utils.executeBashScriptFromLocation(localCodebase, "git checkout master", new ArrayList<String>());

		//
		logger.info("Writing output csv file");
		FileWriter fw = new FileWriter(outputDir + "/nonVuln" + instanceIdx + ".csv");

		for (Function f : functions) {
			fw.write(f.toString() + "\n");
			Utils.writeFile(outputDir + "/word2vec-corpus/" + f.getName() + ".c", f.getBody());
		}

		fw.close();

	}

	private static Function characterizeNonVulnFunction(Function f, String localCodebase, String outputDir,
			Integer nCoChangingThreshold) throws UsersCacheMissException {

		logger.info("Characterizing function: " + f.getName() + " " + f.getFile());

		try {
			Set<String> commitsModifyingFunction = qfe.getCommitsModifyingFunction(f);
			Set<String> functionContributors = github.getCommitsAuthors(commitsModifyingFunction);

			logger.info("Computing function complexity.");
			f.setComplexity(qfe.getMcCabeComplexity(f.getBody()));

			logger.info("Computing function loc.");
			f.setLoc(qfe.getLoc(f.getBody()));

			logger.info("Computing module complexity.");
			f.setModuleComplexity(qfe.getModuleMcCabeComplexity(f));

			logger.info("Computing module loc.");
			f.setModuleLoc(qfe.getModuleLoc(f));

			logger.info("Computing function num changes.");
			f.setnChanges(commitsModifyingFunction.size());

			logger.info("Computing function num authors.");
			f.setnAuthors(functionContributors.size());

			logger.info("Computing module num changes.");
			f.setModuleNChanges(qfe.getModuleNumChanges(f));

			logger.info("Computing module num authors.");
			f.setModuleNAuthors(qfe.getModuleNumAuthors(f));

			/*
			 * logger.info("Computing cochangings complexity.");
			 * f.setCoChangingModuleComplexity( qfe.getCoChangingFunctionsTotalComplexity(f,
			 * nCoChangingThreshold, commitsModifyingFunction));
			 * 
			 * logger.info("Computing cochangings loc."); f.setCoChangingModuleLoc(
			 * qfe.getCoChangingFunctionsTotalLoc(f, nCoChangingThreshold,
			 * commitsModifyingFunction));
			 */

			logger.info("Computing function input params.");
			f.setNumberOfInputParameters(qfe.getNumberOfInputParameters(f));

			logger.info("Computing function declared vars.");
			f.setNumberOfDeclaredVars(qfe.getNumberOfDeclaredVars(f));

			logger.info("Computing function colocated functions.");
			f.setNumberOfCoLocatedFunctions(qfe.getNumberOfCoLocatedFunctions(f));

			logger.info("Computing function lines of comment.");
			f.setNumberOfLinesOfComment(qfe.countCommentedLines(f.getBody()));

			logger.info("Computing function num casts.");
			f.setNumberOfCastExpressions(qfe.getNumberOfCastExpressions(f));

			logger.info("Computing function num sanity checks on input params.");
			f.setNumberOfSanityChecksOnParameters(qfe.getNumberOfSanityChecksOnParameters(f));

			logger.info("Computing function num null pointer accesses.");
			f.setNumberOfNullPtrAccess(qfe.getNumberOfNullPtrAccess(f));

			logger.info("Computing function num null pointer accesses.");
			f.setNumberOfPtrModification(qfe.getNumberOfPtrModification(f));

			// features from github

			if (functionContributors != null && !functionContributors.isEmpty()) {
				logger.info("Computing function average number of followers per contributor.");
				f.setAvgContributorsFollowers(github.getUsersAverageFollowersCount(functionContributors));

				logger.info("Computing function average number of forks per contributor.");
				f.setAvgContributorsForks(github.getUsersAverageForks(functionContributors));

				logger.info("Computing function average number of publis repos per contributor.");
				f.setAvgContributorsPublicRepos(github.getUsersAveragePublicRepoCount(functionContributors));

				logger.info("Computing function average number of stars per contributor.");
				f.setAvgContributorsStars(github.getUsersAverageStars(functionContributors));

				logger.info("Computing function average number of subscribers per contributor.");
				f.setAvgContributorsSubscribers(github.getUsersAverageSubscribers(functionContributors));

				logger.info("Computing function average number of watchers per contributor.");
				f.setAvgContributorsWatchers(github.getUsersAverageWatchers(functionContributors));
			}

			return f;

		} catch (IOException e) {
			logger.error("Problem interacting with Github.");
			e.printStackTrace();
		} catch (ParseException e) {
			logger.error("Problem parsing git log.");
			e.printStackTrace();
		} catch (InterruptedException e) {
			logger.error("Problem invoking external pmccabe.");
			e.printStackTrace();
		}

		return null;
	}
}
