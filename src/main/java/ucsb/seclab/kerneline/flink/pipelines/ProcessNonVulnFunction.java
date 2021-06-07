package ucsb.seclab.kerneline.flink.pipelines;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.flink.api.common.accumulators.IntCounter;
import org.apache.flink.api.common.accumulators.ListAccumulator;
import org.apache.flink.api.common.functions.RichFlatMapFunction;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.util.Collector;
import org.kohsuke.github.GHUser;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Session;
import org.neo4j.driver.v1.StatementResult;
import org.neo4j.driver.v1.Transaction;
import org.neo4j.driver.v1.TransactionWork;
import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.features.extractors.NonVulnQualityFeatureExtractor;
import ucsb.seclab.kerneline.github.GithubDriver;
import ucsb.seclab.kerneline.github.UsersCacheMissException;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public class ProcessNonVulnFunction extends RichFlatMapFunction<String, Function> {

	private static final long serialVersionUID = -5847161739068463748L;

	private final Logger logger = LoggerFactory.getLogger(ProcessNonVulnFunction.class);

	private String lastCommitInPeriod;

	private String localCodebase;

	private String outputDir;

	private String neo4jUrl;

	private Integer neo4jPort;

	private String neo4jUser;

	private String neo4jPass;

	private Integer nCoChangingThreshold;

	private Integer nCoresPerHost;

	private String githubRepoName;
	
	private String githubUser;
	
	private String githubPassword;

	private NonVulnQualityFeatureExtractor qfe;

	private GithubDriver github;

	private List<Function> nonVulnerableFunctions = new ArrayList<Function>();

	private IntCounter nonVulnFunCount = new IntCounter();

	public ProcessNonVulnFunction(String lastCommitInPeriod, String localCodebase, String outputDir, String neo4jUrl,
			Integer neo4jPort, String neo4jUser, String neo4jPass, Integer nCoChangingThreshold, Integer nCoresPerHost,
			String githubRepoName, String githubUser, String githubPassword) {
		this.lastCommitInPeriod = lastCommitInPeriod;
		this.localCodebase = localCodebase;
		this.outputDir = outputDir;
		this.neo4jUrl = neo4jUrl;
		this.neo4jPort = neo4jPort;
		this.neo4jUser = neo4jUser;
		this.neo4jPass = neo4jPass;
		this.nCoChangingThreshold = nCoChangingThreshold;
		this.nCoresPerHost = nCoresPerHost;
		this.githubRepoName = githubRepoName;
		this.githubUser = githubUser;
		this.githubPassword = githubPassword;
		
	}

	@Override
	public void open(Configuration config) throws InterruptedException {
		JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();
		joern.init("bolt://" + this.neo4jUrl + ":" + this.neo4jPort, this.neo4jUser, this.neo4jPass);
		Thread.sleep((long) (Math.random() * 10000
				* (this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + 1)));
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Checking out last commit in considered period.");
		Utils.executeBashScriptFromLocation(
				this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost,
				"git checkout " + this.lastCommitInPeriod, new ArrayList<String>());
		this.qfe = new NonVulnQualityFeatureExtractor(
				this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost, this.outputDir);
		try {
			this.github = new GithubDriver(this.githubRepoName, this.githubUser, this.githubPassword);
		} catch (IOException e) {
			logger.error(
					"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Problems connecting to Github.");
			e.printStackTrace();
		}
		getRuntimeContext().addAccumulator("nonVulnFunCount", this.nonVulnFunCount);
	}

	@Override
	public void close() throws IOException {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Checking out back to the head revision.");
		Utils.executeBashScriptFromLocation(
				this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost,
				"git checkout master", new ArrayList<String>());

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Dumping extracted non vulnerable functions for later word2vec training.");

		if (!Files.exists(Paths.get(outputDir + "/word2vec-corpus"))) {
			(new File(outputDir + "/word2vec-corpus")).mkdirs();
		}

		for (Function ret : nonVulnerableFunctions) {
			Utils.writeFile(outputDir + "/word2vec-corpus/" + ret.getId() + ".c", ret.getBody());
		}

		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(new File(outputDir + "/nonVulnFuns"
				+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"), nonVulnerableFunctions);

	}

	@Override
	public void flatMap(String fName, Collector<Function> out) throws Exception {

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Extracting function: " + fName);

		Record queryRes = JoernNeo4JDriver.getInstance()
				.sendQuery("MATCH (file:File)-[:IS_FILE_OF]->(function:Function{name:'" + fName + "'}) RETURN file")
				.get(0);

		Function f = new Function();
		f.setName(fName);
		f.setFile(queryRes.get("file").get("filepath").toString().replaceAll("\"", ""));
		f.setFileRelative(f.getFile().replaceAll(this.localCodebase + "/", ""));

		String body = Utils.extractFunctionBodyFromFile(this.localCodebase
				+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + "/" + f.getFileRelative(),
				f.getName());

		if (body == null) {
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Dropping joern retrieved function due to empty extracted body: " + f.getName() + " "
					+ f.getFile());
		} else {
			f.setBody(body);

			f.setIsVulnerable(false);
			f.setSha(DigestUtils.sha256Hex(this.lastCommitInPeriod + f.getName()));
			f.setId(f.getName() + "_" + f.getFileRelative().replaceAll("/", "%").replaceAll("\\.c", ""));

			f = this.characterizeNonVulnFunction(f);
			this.nonVulnFunCount.add(1);
			this.nonVulnerableFunctions.add(f);
			out.collect(f);

		}

	}

	private Function characterizeNonVulnFunction(Function f) throws IOException, InterruptedException, ParseException, UsersCacheMissException {

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Characterizing function: "
				+ f.getName() + " " + f.getFile());

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting commits in which " + f.getName() + " was modified.");
		Set<String> commitsModifyingFunction = qfe.getCommitsModifyingFunction(f);
		
		logger.info(
				"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting commits authors from Github.");
		Set<String> functionContributors = this.github.getCommitsAuthors(commitsModifyingFunction);

		logger.info(
				"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function num changes.");
		f.setnChanges(commitsModifyingFunction.size());

		logger.info(
				"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function num authors.");
		f.setnAuthors(functionContributors.size());

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function complexity.");
		f.setComplexity(this.qfe.getMcCabeComplexity(f.getBody()));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function loc.");
		f.setLoc(this.qfe.getLoc(f.getBody()));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing module complexity.");
		f.setModuleComplexity(this.qfe.getModuleMcCabeComplexity(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing module loc.");
		f.setModuleLoc(this.qfe.getModuleLoc(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing module num changes.");
		f.setModuleNChanges(this.qfe.getModuleNumChanges(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing module num authors.");
		f.setModuleNAuthors(this.qfe.getModuleNumAuthors(f));

		/*
		 * logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() +
		 * "] Computing cochangings complexity.");
		 * f.setCoChangingModuleComplexity(this.qfe.
		 * getCoChangingFunctionsTotalComplexity(f, this.nCoChangingThreshold,
		 * commitsModifyingFunction));
		 * 
		 * logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() +
		 * "] Computing cochangings loc.");
		 * f.setCoChangingModuleLoc(this.qfe.getCoChangingFunctionsTotalLoc(f,
		 * this.nCoChangingThreshold, commitsModifyingFunction));
		 */

		logger.info(
				"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function input params.");
		f.setNumberOfInputParameters(this.qfe.getNumberOfInputParameters(f));

		logger.info(
				"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function declared vars.");
		f.setNumberOfDeclaredVars(this.qfe.getNumberOfDeclaredVars(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Computing function colocated functions.");
		f.setNumberOfCoLocatedFunctions(this.qfe.getNumberOfCoLocatedFunctions(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Computing function lines of comment.");
		f.setNumberOfLinesOfComment(this.qfe.countCommentedLines(f.getBody()));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Computing function num casts.");
		f.setNumberOfCastExpressions(this.qfe.getNumberOfCastExpressions(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Computing function num sanity checks on input params.");
		f.setNumberOfSanityChecksOnParameters(this.qfe.getNumberOfSanityChecksOnParameters(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Computing function num null pointer accesses.");
		f.setNumberOfNullPtrAccess(this.qfe.getNumberOfNullPtrAccess(f));

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
				+ "] Computing function num null pointer accesses.");
		f.setNumberOfPtrModification(this.qfe.getNumberOfPtrModification(f));

		// features from github

		if (functionContributors != null && !functionContributors.isEmpty()) {
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Computing function average number of followers per contributor.");
			f.setAvgContributorsFollowers(this.github.getUsersAverageFollowersCount(functionContributors));

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Computing function average number of forks per contributor.");
			f.setAvgContributorsForks(this.github.getUsersAverageForks(functionContributors));

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Computing function average number of publis repos per contributor.");
			f.setAvgContributorsPublicRepos(this.github.getUsersAveragePublicRepoCount(functionContributors));

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Computing function average number of stars per contributor.");
			f.setAvgContributorsStars(this.github.getUsersAverageStars(functionContributors));

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Computing function average number of watchers per contributor.");
			f.setAvgContributorsWatchers(this.github.getUsersAverageWatchers(functionContributors));
		}

		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting function AST.");
		f.setAst(JoernNeo4JDriver.getInstance().getAst(f.getName(), f.getFile()));

		return f;
	}

}
