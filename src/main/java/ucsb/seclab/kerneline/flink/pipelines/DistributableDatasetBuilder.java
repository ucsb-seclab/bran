package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.flink.api.java.tuple.Tuple2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.medallia.word2vec.Searcher.UnknownWordException;

import fileWalker.OrderedWalker;
import fileWalker.SourceFileWalker;
import outputModules.neo4j.Neo4JIndexer;
import tools.index.Indexer;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.sources.CVEs;
import ucsb.seclab.kerneline.utils.FunctionNotFoundException;
import ucsb.seclab.kerneline.utils.KernelineConfig;
import ucsb.seclab.kerneline.utils.Utils;

public class DistributableDatasetBuilder {

	private static final Logger logger = LoggerFactory.getLogger(DistributableDatasetBuilder.class);

	private CVEs cves = null;

	private static KernelineConfig config = null;

	private static final String NVD_JSON_URL_PREFIX = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-";

	public static void main(String[] args)
			throws RuntimeException, IOException, InterruptedException, UnknownWordException, ParseException {

		DistributableDatasetBuilder dsb = new DistributableDatasetBuilder(args[0]);

		logger.info("Initializing.");
		dsb.init();

		logger.info("Getting vulnerable functions from codebase and building JSON outptut.");
		Integer vulnFunCount = dsb.extractVulnFunctions();
		logger.info("Total number of extracted vulnerable functions: " + vulnFunCount);

		logger.info("Extracting non vulnerable functions.");
		dsb.extractNonVulnFunctions(vulnFunCount);

		logger.info("Dataset creation completed.");

		dsb.close();

	}

	public void close() {
		if (config.isStartNeo4J()) {
			// stop neo4j server
			logger.info("Stopping mainh Neo4J instance.");
			Utils.executeBashScriptFromLocation(config.getPathToNeo4JInstallation(), "./bin/neo4j stop",
					new ArrayList<String>());
		}
	}

	public void setLastCommitInPeriod() {
		config.setLastCommitInPeriod(this.getLastCommitInPeriod());
	}

	private void downloadNVD() throws IOException {
		Integer tmpYear = config.getStartYear();
		HttpURLConnection connection = null;
		URL url = null;
		InputStream input = null;
		FileOutputStream output = null;
		byte[] buf = new byte[1024];
		int n;

		while (tmpYear <= config.getEndYear()) {

			url = new URL(NVD_JSON_URL_PREFIX + tmpYear + ".json.zip");
			connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("GET");
			input = connection.getInputStream();
			output = new FileOutputStream(config.getNvdRootDir() + "/nvdcve-1.0-" + tmpYear + ".json.zip");
			n = input.read(buf);
			while (n >= 0) {
				output.write(buf, 0, n);
				n = input.read(buf);
			}
			output.flush();

			Utils.unzipFile(config.getNvdRootDir() + "/nvdcve-1.0-" + tmpYear + ".json.zip", config.getNvdRootDir());
			Files.delete(Paths.get(config.getNvdRootDir() + "/nvdcve-1.0-" + tmpYear + ".json.zip"));
			tmpYear = tmpYear + 1;

		}

		output.close();

	}

	private String getLastCommitInPeriod() {
		String lastCommitInPeriod = null;

		String[] gitLog = Utils.executeBashScriptFromLocation(config.getLocalCodebase(),
				"git --no-pager log --reverse --oneline", new ArrayList<String>()).split("\n");
		String commitId = null;
		int tmpCommitYear;
		boolean foundLastCommit = false;

		// parse the onelined and reversed log
		logger.debug("Parsing onelined reversed git log line by line (commit by commit).");
		for (int i = 0; i < gitLog.length && !foundLastCommit; i++) {
			commitId = gitLog[i].split(" ")[0];
			logger.debug("Commit: " + commitId);

			// get the year of the commit
			tmpCommitYear = Integer.parseInt(Utils.executeBashScriptFromLocation(config.getLocalCodebase(),
					"git show -s --format=%ci " + commitId, new ArrayList<String>()).split("-")[0]);

			if (config.getStartYear() <= tmpCommitYear && tmpCommitYear <= config.getEndYear()) {
				// if the year of the commit is within startYear and endYear set it as the
				// current lastCommitInPeriod
				logger.debug("The year of the commit falls within the considered interval.");
				lastCommitInPeriod = commitId;
			} else if (tmpCommitYear > config.getEndYear()) {
				logger.debug(
						"The year of the commit is greater than the upper bound for the considered interval (last commit in period found).");
				// if the year of the commit is greater than endYear, the last commit in the
				// period has been found and is currently in lastCommitInPeriod
				foundLastCommit = true;
			} else {
				// if the year of the commit is smaller that startYear just move ahead on the
				// log
				logger.debug(
						"The year of the commit is smaller than the lower bound for the considered interval. Moving to the next commit.");
			}
		}

		return lastCommitInPeriod;

	}

	private void generateJoernDatabase() {
		SourceFileWalker sourceFileWalker = new OrderedWalker();

		Indexer indexer = new Neo4JIndexer();
		indexer.setOutputDir(config.getPathToNeo4JDatabaseDirectory());
		indexer.initialize();
		sourceFileWalker.addListener(indexer);
		try {
			if (config.getSubfolders() != null && config.getSubfolders().size() > 0) {
				String[] dirToWalk = new String[config.getSubfolders().size()];
				int cont = 0;
				for (String subfolder : config.getSubfolders()) {
					dirToWalk[cont] = config.getLocalCodebase() + "/" + subfolder;
					cont = cont + 1;
				}
				sourceFileWalker.walk(dirToWalk);
			} else {
				String[] dirToWalk = new String[1];
				dirToWalk[0] = config.getLocalCodebase();
				sourceFileWalker.walk(dirToWalk);
			}

		} catch (IOException err) {
			System.err.println("Error walking source files: " + err.getMessage());
		} finally {
			indexer.shutdown();
		}
	}

	private void loadJoernNeo4JDatabase() {

		// checkout the last commit of the codebase which falls into year endYear
		logger.info("Checking out last commit in considered period: " + config.getLastCommitInPeriod());
		Utils.executeBashScriptFromLocation(config.getLocalCodebase(), "git checkout " + config.getLastCommitInPeriod(),
				new ArrayList<String>());

		// run joern against the extracted commit
		logger.info("Generating Joern Neo4J database");
		this.generateJoernDatabase();

		// checkout the repository back to the HEAD
		logger.info("Checking out codebase back to HEAD revision.");
		Utils.executeBashScriptFromLocation(config.getLocalCodebase(), "git checkout master", new ArrayList<String>());

	}

	private void extractNonVulnFunctions(Integer vulnFunCount) {

		JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();

		try {
			List<String> codebaseFunctions = joern.getAllFunctionsFromCodebase(vulnFunCount * 10,
					config.getSubfolders());
			logger.info("Number of considered non vulnerable functions: " + codebaseFunctions.size());

			NonVulnerablePipeline vulnFlinkPipeline = new NonVulnerablePipeline();

			try {
				logger.info("Launching pipeline for extracting non vulnerable functions.");
				vulnFlinkPipeline.extractNonVulnFunctions(codebaseFunctions, config.getLastCommitInPeriod(),
						config.getLocalCodebase(), config.getOutputDir(), config.getnPhisicalHosts(),
						config.getnCoresPerHost(), config.getNeo4jUrl(), config.getNeo4jPort(), config.getNeo4jUser(),
						config.getNeo4jPassword(), config.getnCoChangingThreshold(), config.getGithubRepoName(),
						config.getGithubUser(), config.getGithubPassword());
			} catch (Exception e) {
				logger.info("Problems running Flink pipeline for extracting non vulnerable functions.");
				e.printStackTrace();
			}

		} catch (FunctionNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private Integer extractVulnFunctions() {

		Integer tmpYear = config.getStartYear();
		List<String> currentCVEs = new ArrayList<String>();

		// for each CVE (or up to a given number of CVEs)
		while (tmpYear <= config.getEndYear()) {
			if(this.cves.getCVEs(tmpYear) != null) {
				currentCVEs.addAll(this.cves.getCVEs(tmpYear));
			}
			tmpYear = tmpYear + 1;
		}

		logger.info("Found " + currentCVEs.size() + " CVEs for the considered period.");

		VulnerablePipeline vulnFlinkPipeline = new VulnerablePipeline();

		Integer vulnFunCount;
		try {
			vulnFunCount = vulnFlinkPipeline.extractVulnFunctions(currentCVEs, config.getNvdRootDir(),
					config.getLinuxCVEsMappingFile(), config.getStartYear(), config.getEndYear(), config.getOutputDir(),
					config.getLocalCodebase(), config.getSubfolders(), config.getnPhisicalHosts(),
					config.getnCoresPerHost(), config.getPathToNeo4JInstallation(),
					config.getPathToNeo4JDatabaseDirectory(), config.getnCoChangingThreshold(),
					config.getGithubRepoName(), config.getExtractFixedFunctions(),
					config.getExtractOnlyCVEsFromMappingFile(), config.getGithubUser(), config.getGithubPassword());
			return vulnFunCount;

		} catch (Exception e) {
			logger.error("Problems running vulnerbale pipeline.");
			e.printStackTrace();
			throw new RuntimeException(e.getMessage(), e.getCause());
		}

	}

	public DistributableDatasetBuilder(String pathToConfigFile) {
		KernelineConfig tmpConfig = KernelineConfig.getInstance();
		try {
			tmpConfig.init(pathToConfigFile);
			config = tmpConfig;
			if (config.getLocalCodebase() == null) {
				logger.error("The config file should give the path to the local codebase to be analyzed. Exiting...");
				System.exit(0);
			}
		} catch (FileNotFoundException e) {
			logger.error("The input config file couldn't be found.");
			e.printStackTrace();
		} catch (IOException e) {
			logger.error("Problems opening the input config file.");
			e.printStackTrace();
		}
	}

	private void init() {

		if (config.isDownloadNvd()) {
			logger.info("Downloading from NVD.");
			try {
				this.downloadNVD();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		this.cves = new CVEs(Paths.get(config.getCvesLocation()), config.getStartYear(), config.getEndYear());

		if (config.getLastCommitInPeriod() == null) {
			this.setLastCommitInPeriod();
		}

		if (config.isLoadJoernNeo4JDatabase()) {
			logger.info("Generating Joern database and load it into Neo4J.");
			this.loadJoernNeo4JDatabase();
		}

		if (config.isStartNeo4J()) {
			// start a local neo4j instance to point to the created database
			// we assume the neo4j installation to be configured to already point to a
			// database called "joernIndex" as exported here
			// in the future we may check for this configuration before starting the server
			logger.info("Starting Neo4J main instance.");
			Utils.executeBashScriptFromLocation(config.getPathToNeo4JInstallation(), "./bin/neo4j start",
					new ArrayList<String>());

			while (!this.pingNeo4J()) {

			}
		}

		// connect to the driver to the database instance
		logger.info("Initializing Neo4J driver.");
		JoernNeo4JDriver joern = JoernNeo4JDriver.getInstance();
		joern.init("bolt://" + config.getNeo4jUrl() + ":" + config.getNeo4jPort(), config.getNeo4jUser(),
				config.getNeo4jPassword());

		if (config.isStartNeo4J()) {
			joern.initializeFileIndex();
			joern.initializeFunctionIndex();
			joern.initializeCFGInitIndex();
		}
	}

	public static boolean pingNeo4J() {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress(config.getNeo4jUrl(), config.getNeo4jPort()), 30000);
			return true;
		} catch (IOException e) {
			return false; // Either timeout or unreachable or failed DNS lookup.
		}
	}

}
