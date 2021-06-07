package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.flink.api.common.functions.RichFlatMapFunction;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.util.Collector;
import org.kohsuke.github.GHUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import fileWalker.OrderedWalker;
import fileWalker.SourceFileWalker;
import outputModules.neo4j.Neo4JIndexer;
import tools.index.Indexer;
import ucsb.seclab.kerneline.features.extractors.VulnQualityFeatureExtractor;
import ucsb.seclab.kerneline.github.GithubDriver;
import ucsb.seclab.kerneline.github.UsersCacheMissException;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Value;
import org.neo4j.driver.v1.exceptions.ServiceUnavailableException;

import java.util.stream.Collectors;

public class CharacterizeVulnFunction extends RichFlatMapFunction<String, Function> {

	private static final long serialVersionUID = 2015841523207791308L;

	private static final Logger logger = LoggerFactory.getLogger(CharacterizeVulnFunction.class);

	private String outputDir;

	private String localCodebase;

	private String pathToNeo4JInstallation;

	private Integer nCoChangingThreshold;

	private Integer nCoresPerHost;

	private String githubRepoName;
	
	private String githubUser;
	
	private String githubPassword;

	private List<Function> vulnerableFunctions = new ArrayList<Function>();

	private VulnQualityFeatureExtractor qfe;

	private GithubDriver github;
		
	private String foldersToDrop = null;
	
	private String foldersToKeep = null;

	@Override
	public void close() {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Dumping extracted functions for later word2vec training.");
		try {

			(new File(outputDir + "/word2vec-corpus")).mkdirs();
			for (Function ret : vulnerableFunctions) {
				Utils.writeFile(outputDir + "/word2vec-corpus/" + ret.getId() + ".c", ret.getBody());
			}

			ObjectMapper mapper = new ObjectMapper();
			mapper.writeValue(new File(outputDir + "/vulnFuns"
					+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"),
					this.vulnerableFunctions);
		} catch (IOException e) {
			logger.error("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Problems dumping word2vec-corpus and negative samples.");
			e.printStackTrace();
		}

	}

	@Override
	public void open(Configuration config) {
		if (getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost == 0) {
			this.generateJoernDatabase();
			this.startNeo4J();

			JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();

			boolean connected = false;

			while (!connected) {
				try {
					logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Trying to connect Neo4J.");
					joern.init("bolt://localhost:7688", "", "");
					connected = true;
				} catch (ServiceUnavailableException e) {
					logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Neo4J is still not started");
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}

			joern.initializeFileIndex();
			joern.initializeFunctionIndex();
			joern.initializeCFGInitIndex();
			
			joern.setFilesFolder(foldersToKeep);
		} else {

			JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();
			
			boolean connected = false;

			while (!connected) {
				try {
					logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Trying to connect Neo4J.");
					joern.init("bolt://localhost:7688", "", "");
					connected = true;
				} catch (ServiceUnavailableException e) {
					logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Neo4J is still not started");
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}

			boolean indexesReady = false;

			while (!indexesReady) {
				logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Checking for indexes availability in Neo4J.");
				List<Record> indexes = joern.sendQuery("CALL db.indexes;");

				for (Record idx : indexes) {
					if (idx.get("description").toString().contains("CFGEntryNode")
							&& idx.get("state").toString().contains("ONLINE")) {
						indexesReady = true;
					}
				}
			}
			
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Indexes are available, start processing.");
		}

		this.localCodebase = this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost;
		this.qfe = new VulnQualityFeatureExtractor(this.localCodebase, this.outputDir, this.foldersToKeep);
		try {
			this.github = new GithubDriver(this.githubRepoName, this.githubUser, this.githubPassword);
		} catch (IOException e) {
			logger.error("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Problems connecting to Github.");
			e.printStackTrace();
		}
	}

	public CharacterizeVulnFunction(Map<String, Object> config) {
		this.outputDir = (String) config.get("outputDir");
		this.localCodebase = (String) config.get("localCodebase");
		this.pathToNeo4JInstallation = (String) config.get("pathToNeo4JInstallation") + "_vuln";
		this.nCoChangingThreshold = (Integer) config.get("nCoChangingThreshold");
		this.nCoresPerHost = (Integer) config.get("nCoresPerHost");
		this.githubRepoName = (String) config.get("githubRepoName");
		this.githubUser = (String) config.get("githubUser");
		this.githubPassword = (String) config.get("githubPassword");

		if((Boolean) config.get("extractFixedFunctions")) {
			this.foldersToDrop = "old_files";
			this.foldersToKeep = "new_files";
		} else {
			this.foldersToDrop = "new_files";
			this.foldersToKeep = "old_files";			
		}
	}

	public void flatMap(String command, Collector<Function> out) throws JsonParseException, JsonMappingException, IOException, InterruptedException, UsersCacheMissException, ParseException {

		if (command.equals("START")) {
			ObjectMapper mapper = new ObjectMapper();
			List<Function> functions = mapper
					.readValue(
							new File(outputDir + "/vulnFuns"
									+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"),
							new TypeReference<List<Function>>() {
							});

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting " + functions.size()
					+ " assigned vulnerable functions.");
			if (functions.size() > 0) {
				List<HashSet<Function>> functionsPerCommit = new ArrayList<HashSet<Function>>();

				Map<String, List<Function>> groups = functions.parallelStream()
						.collect(Collectors.groupingBy(Function::getFixingCommit));

				for (String c : groups.keySet()) {
					functionsPerCommit.add(new HashSet<Function>(groups.get(c)));
				}

				logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
						+ "] Assigned functions span over " + functionsPerCommit.size() + " commits.");

				for (HashSet<Function> fSet : functionsPerCommit) {
					if (fSet.size() > 0) {
						logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
								+ "]Checking out fixing commit: " + fSet.iterator().next().getFixingCommit());

						Utils.executeBashScriptFromLocation(this.localCodebase,
								"git checkout " + fSet.iterator().next().getFixingCommit(), new ArrayList<String>());
						try {
							Thread.sleep(3000);
						} catch (InterruptedException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						for (Function f : fSet) {

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "]Characterizing function: " + f.getName() + " " + f.getFile());

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting commits in which " + f.getName() + " was modified.");
								Set<String> commitsModifyingFunction = qfe.getCommitsModifyingFunction(f);
								
								logger.info(
										"[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting commits authors from Github.");
								Set<String> functionContributors = this.github
										.getCommitsAuthors(commitsModifyingFunction);

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num changes.");
								f.setnChanges(commitsModifyingFunction.size());

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num authors.");
								f.setnAuthors(functionContributors.size());

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function complexity.");
								f.setComplexity(this.qfe.getMcCabeComplexity(f.getBody()));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function loc.");
								f.setLoc(this.qfe.getLoc(f.getBody()));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing module complexity.");
								f.setModuleComplexity(this.qfe.getModuleMcCabeComplexity(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing module loc.");
								f.setModuleLoc(this.qfe.getModuleLoc(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing module num changes.");
								f.setModuleNChanges(this.qfe.getModuleNumChanges(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing module num authors.");
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

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function input params.");
								f.setNumberOfInputParameters(this.qfe.getNumberOfInputParameters(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function declared vars.");
								f.setNumberOfDeclaredVars(this.qfe.getNumberOfDeclaredVars(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function colocated functions.");
								f.setNumberOfCoLocatedFunctions(this.qfe.getNumberOfCoLocatedFunctions(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function lines of comment.");
								f.setNumberOfLinesOfComment(this.qfe.countCommentedLines(f.getBody()));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num casts.");
								f.setNumberOfCastExpressions(this.qfe.getNumberOfCastExpressions(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num sanity checks on input params.");
								f.setNumberOfSanityChecksOnParameters(
									this.qfe.getNumberOfSanityChecksOnParameters(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num null pointer accesses.");
								f.setNumberOfNullPtrAccess(this.qfe.getNumberOfNullPtrAccess(f));

								logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
										+ "] Computing function num pointer modifications.");
								f.setNumberOfPtrModification(this.qfe.getNumberOfPtrModification(f));

								// features from github

								if (functionContributors != null && !functionContributors.isEmpty()) {
									logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
											+ "] Computing function average number of followers per contributor.");
									f.setAvgContributorsFollowers(
											this.github.getUsersAverageFollowersCount(functionContributors));

									logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
											+ "] Computing function average number of forks per contributor.");
									f.setAvgContributorsForks(this.github.getUsersAverageForks(functionContributors));

									logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
											+ "] Computing function average number of publis repos per contributor.");
									f.setAvgContributorsPublicRepos(
											this.github.getUsersAveragePublicRepoCount(functionContributors));

									logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
											+ "] Computing function average number of stars per contributor.");
									f.setAvgContributorsStars(this.github.getUsersAverageStars(functionContributors));

									logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
											+ "] Computing function average number of watchers per contributor.");
									f.setAvgContributorsWatchers(
											this.github.getUsersAverageWatchers(functionContributors));
								}
								
								if(this.foldersToKeep.equals("new_files")) {
									f.setIsVulnerable(false);
								}

								this.vulnerableFunctions.add(f);
								out.collect(f);

						}
						Utils.executeBashScriptFromLocation(this.localCodebase, "git checkout master",
								new ArrayList<String>());
					}

				}
			}
		}

	}

	private void generateJoernDatabase() {
		SourceFileWalker sourceFileWalker = new OrderedWalker();

		Indexer indexer = new Neo4JIndexer();
		indexer.setOutputDir(this.pathToNeo4JInstallation + "/data/databases/joernIndex");
		indexer.initialize();
		sourceFileWalker.addListener(indexer);
				
		try {

			String[] dirToWalk = new String[1];
			for (File f : this.findDirectoriesWithSameName(this.foldersToDrop, new File(this.outputDir))) {
				String[] entries = f.list();
				for (String s : entries) {
					File currentFile = new File(f.getPath(), s);
					currentFile.delete();
				}
				f.delete();
			}
			dirToWalk[0] = this.outputDir;
			sourceFileWalker.walk(dirToWalk);

		} catch (IOException err) {
			logger.error("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Error walking source files: " + err.getMessage());
		} finally {
			indexer.shutdown();
		}
	}

	private List<File> findDirectoriesWithSameName(String name, File root) {
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

	private void startNeo4J() {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Starting local Neo4J instance.");
		Utils.executeBashScriptFromLocation(this.pathToNeo4JInstallation, "./bin/neo4j start", new ArrayList<String>());
		try {
			Thread.sleep(60000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
