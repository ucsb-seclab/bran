package ucsb.seclab.kerneline.standalone;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.kohsuke.github.GHUser;
import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.features.extractors.VulnQualityFeatureExtractor;
import ucsb.seclab.kerneline.flink.pipelines.ExtractVulnFunction;
import ucsb.seclab.kerneline.github.GithubDriver;
import ucsb.seclab.kerneline.github.UsersCacheMissException;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public class VulnFunctionCharacterizer {

	private static final Logger logger = LoggerFactory.getLogger(VulnFunctionCharacterizer.class);

	/*
	 * args[0] = index of this parallel instance
	 */
	/*
	 * args[1] = path to codebase
	 */
	/*
	 * args[2] = path to result folder
	 */
	/*
	 * args[3] = nCoChangingThreshold (just a config parameter relevant to the
	 * function characterization)
	 */
	/*
	 * args[4] = the name of the github repo from where the local codebase was
	 * cloned
	 */
	/*
	 * args[5] = ip of the neo4j instance containing the database built from the
	 * extracted vulnerable functions at the end of the first step
	 */
	/*
	 * args[6] = port of the neo4j instance containing the database built from the
	 * extracted vulnerable functions at the end of the first step
	 */

	// OTHER ASSUMPTIONS AND REQUIREMENTS
	/*
	 * neo4j is assumed to be deployed without authentication enabled
	 * (dbms.security.auth_enabled=false) git is installed on the pod machine
	 * pmccabe is installed on the pod machine (sudo apt-get install pmccabe) use
	 * neo4j 3.2.12 for joern compatibility neo4j configured with format migration
	 * enabled (dbms.allow_format_migration=true) neo4j configured with bolt
	 * connector enabled (dbms.connector.bolt.enabled=true)
	 */
	// STEPS TO BE DONE AFTER THE EXECUTION OF VulnFunctionExtractor
	/*
	 * run joern (properly configured as above) against the output folder copy the
	 * generated database to the ./data/database directory of the neo4j installation
	 * run neo4j (wait for migration to finish)
	 */
	public static void main(String[] args) throws JsonParseException, JsonMappingException, IOException, UsersCacheMissException {

		Integer instanceIdx = 1;
		String localCodebase = args[0];
		String outputDir = args[1];
		Integer nCoChangingThreshold = Integer.parseInt(args[2]);
		String githubRepoName = args[3];
		String neo4jIp = args[4];
		Integer neo4jPort = Integer.parseInt(args[5]);
		String githubUser = args[6];
		String githubPassword = args[7];

		// this should be actually loaded from the remote file pointed by args[2]
		ObjectMapper mapper = new ObjectMapper();
		List<Function> functions = mapper.readValue(new File(outputDir + "/vulnFuns" + instanceIdx + ".json"),
				new TypeReference<List<Function>>() {
				});

		VulnQualityFeatureExtractor qfe = new VulnQualityFeatureExtractor(localCodebase, outputDir, null);

		GithubDriver github;

		JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();
		joern.init("bolt://" + neo4jIp + ":" + neo4jPort + "", "", "");

		try {
			github = new GithubDriver(githubRepoName, githubUser, githubPassword);

			logger.info("Number of functions to characterize: " + functions.size());

			for (Function f : functions) {
				if (JoernNeo4JDriver.getInstance().getCFGInit(f, outputDir) != null) {
					logger.info("Characterizing function: " + f.getName() + " " + f.getFile());

					logger.info("Checking out fixing commit: " + f.getFixingCommit());

					// distributed env
					Utils.executeBashScriptFromLocation(localCodebase,
							"git checkout " + functions.iterator().next().getFixingCommit(), new ArrayList<String>());
					try {
						Thread.sleep(3000);
					} catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

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
					 * logger.info("[Worker " + getRuntimeContext().getIndexOfThisSubtask() +
					 * "] Computing cochangings complexity."); f.setCoChangingModuleComplexity(qfe.
					 * getCoChangingFunctionsTotalComplexity(f, nCoChangingThreshold,
					 * commitsModifyingFunction));
					 * 
					 * logger.info("[Worker " + getRuntimeContext().getIndexOfThisSubtask() +
					 * "] Computing cochangings loc.");
					 * f.setCoChangingModuleLoc(qfe.getCoChangingFunctionsTotalLoc(f,
					 * nCoChangingThreshold, commitsModifyingFunction));
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

					logger.info("Computing function num pointer modifications.");
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

				} else {
					logger.info("Impossible to retrieve CFG for current function from Neo4J.");
				}

			}

			logger.info("Checking out back to head revision.");
			Utils.executeBashScriptFromLocation(localCodebase, "git checkout master", new ArrayList<String>());

			//
			logger.info("Writing output csv file");
			FileWriter fw = new FileWriter(outputDir + "/vuln" + instanceIdx + ".csv");

			if (!Files.exists(Paths.get(outputDir + "/word2vec-corpus"), LinkOption.NOFOLLOW_LINKS)) {
				new File(outputDir + "/word2vec-corpus").mkdirs();
			}

			for (Function f : functions) {
				fw.write(f.toString() + "\n");
				Utils.writeFile(outputDir + "/word2vec-corpus/" + f.getName() + ".c", f.getBody());
			}

			fw.close();
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

	}

}
