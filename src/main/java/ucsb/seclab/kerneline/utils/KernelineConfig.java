package ucsb.seclab.kerneline.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class KernelineConfig {

	private String nvdRootDir = null;

	private String neo4jUrl = "localhost";

	private Integer neo4jPort = 7687;

	private String neo4jUser = "";

	private String neo4jPassword = "";

	private String cvesLocation = null;

	private String outputDir = null;

	private String localCodebase = null;

	private List<String> subfolders = null;

	private Integer startYear = null;

	private Integer endYear = null;

	private boolean downloadNvd = true;

	private Integer nCoChangingThreshold = null;

	private String pathToNeo4JInstallation = null;

	private boolean loadJoernNeo4JDatabase = true;

	private boolean startNeo4J = true;

	private String lastCommitInPeriod = null;

	private Integer nPhisicalHosts = null;
	
	private Integer nCoresPerHost = null;
	
	private String githubRepoName = null;

	private String githubUser = null;

	private String githubPassword = null;
	
	private Boolean extractFixedFunctions = null;
	
	private String linuxCVEsMappingFile = null;
	
	private Boolean extractOnlyCVEsFromMappingFile = false;
	
	public Boolean getExtractOnlyCVEsFromMappingFile() {
		return extractOnlyCVEsFromMappingFile;
	}

	public void setExtractOnlyCVEsFromMappingFile(Boolean extractOnlyCVEsFromMappingFile) {
		this.extractOnlyCVEsFromMappingFile = extractOnlyCVEsFromMappingFile;
	}

	public String getLinuxCVEsMappingFile() {
		return linuxCVEsMappingFile;
	}

	public void setLinuxCVEsMappingFile(String linuxCVEsMappingFile) {
		this.linuxCVEsMappingFile = linuxCVEsMappingFile;
	}

	private static KernelineConfig instance = null;
	

	private KernelineConfig() {

	}

	public static KernelineConfig getInstance() {
		if (instance == null) {
			instance = new KernelineConfig();
		}

		return instance;
	}

	public void init(String pathToPropertyFile) throws FileNotFoundException, IOException {
		Properties prop = new Properties();
		prop.load(new FileInputStream(pathToPropertyFile));
		this.nvdRootDir = prop.getProperty("nvdRootDir");
		this.neo4jUrl = prop.getProperty("neo4jUrl");
		this.neo4jPort = Integer.parseInt(prop.getProperty("neo4jPort"));
		this.neo4jUser = prop.getProperty("neo4jUser");
		this.neo4jPassword = prop.getProperty("neo4jPassword");
		this.cvesLocation = prop.getProperty("cvesLocation");
		this.outputDir = prop.getProperty("outputDir");
		this.localCodebase = prop.getProperty("localCodebase");
		if(prop.getProperty("subfolders") != null){
			this.subfolders = Arrays.asList(prop.getProperty("subfolders").split(":"));
		} else {
			this.subfolders = new ArrayList<String>();
		}
		this.startYear = Integer.parseInt(prop.getProperty("startYear"));
		this.endYear = Integer.parseInt(prop.getProperty("endYear"));
		this.downloadNvd = Boolean.parseBoolean(prop.getProperty("downloadNvd"));
		this.nCoChangingThreshold = Integer.parseInt(prop.getProperty("nCoChangingThreshold"));
		this.pathToNeo4JInstallation = prop.getProperty("pathToNeo4JInstallation");
		this.loadJoernNeo4JDatabase = Boolean.parseBoolean(prop.getProperty("loadJoernNeo4JDatabase"));
		this.startNeo4J = Boolean.parseBoolean(prop.getProperty("startNeo4J"));
		this.lastCommitInPeriod = prop.getProperty("lastCommitInPeriod");
		this.nPhisicalHosts = Integer.parseInt(prop.getProperty("nPhisicalHosts"));
		this.nCoresPerHost = Integer.parseInt(prop.getProperty("nCoresPerHost"));
		this.githubRepoName = prop.getProperty("githubRepoName");
		this.extractFixedFunctions = Boolean.parseBoolean(prop.getProperty("extractFixedFunctions"));
		this.linuxCVEsMappingFile = prop.getProperty("linuxCVEsMappingFile");
		this.extractOnlyCVEsFromMappingFile = Boolean.parseBoolean(prop.getProperty("extractOnlyCVEsFromMappingFile"));
		if (prop.getProperty("githubUser") != null && prop.getProperty("githubUser") != null) {
			this.githubUser = prop.getProperty("githubUser");
			this.githubPassword = prop.getProperty("githubPassword");
		} else {
			throw new RuntimeException("GitHub user and password should be provided.");
		}
	}

	public String getGithubUser() {
		return githubUser;
	}

	public void setGithubUser(String githubUser) {
		this.githubUser = githubUser;
	}

	public String getGithubPassword() {
		return githubPassword;
	}

	public void setGithubPassword(String githubPassword) {
		this.githubPassword = githubPassword;
	}

	public Boolean getExtractFixedFunctions() {
		return extractFixedFunctions;
	}

	public void setExtractFixedFunctions(Boolean extractFixedFunctions) {
		this.extractFixedFunctions = extractFixedFunctions;
	}

	public String getGithubRepoName() {
		return githubRepoName;
	}

	public void setGithubRepoName(String githubRepoName) {
		this.githubRepoName = githubRepoName;
	}

	public Integer getnPhisicalHosts() {
		return nPhisicalHosts;
	}

	public void setnPhisicalHosts(Integer nPhisicalHosts) {
		this.nPhisicalHosts = nPhisicalHosts;
	}

	public Integer getnCoresPerHost() {
		return nCoresPerHost;
	}

	public void setnCoresPerHost(Integer nCoresPerHost) {
		this.nCoresPerHost = nCoresPerHost;
	}

	public String getNvdRootDir() {
		return nvdRootDir;
	}

	public void setNvdRootDir(String nvdRootDir) {
		this.nvdRootDir = nvdRootDir;
	}

	public String getNeo4jUrl() {
		return neo4jUrl;
	}

	public void setNeo4jUrl(String neo4jUrl) {
		this.neo4jUrl = neo4jUrl;
	}

	public Integer getNeo4jPort() {
		return neo4jPort;
	}

	public void setNeo4jPort(Integer neo4jPort) {
		this.neo4jPort = neo4jPort;
	}

	public String getNeo4jUser() {
		return neo4jUser;
	}

	public void setNeo4jUser(String neo4jUser) {
		this.neo4jUser = neo4jUser;
	}

	public String getNeo4jPassword() {
		return neo4jPassword;
	}

	public void setNeo4jPassword(String neo4jPassword) {
		this.neo4jPassword = neo4jPassword;
	}

	public String getCvesLocation() {
		return cvesLocation;
	}

	public void setCvesLocation(String cvesLocation) {
		this.cvesLocation = cvesLocation;
	}

	public String getOutputDir() {
		return outputDir;
	}

	public void setOutputDir(String outputDir) {
		this.outputDir = outputDir;
	}

	public String getLocalCodebase() {
		return localCodebase;
	}

	public void setLocalCodebase(String localCodebase) {
		this.localCodebase = localCodebase;
	}

	public List<String> getSubfolders() {
		return subfolders;
	}

	public void setSubfolders(List<String> subfolders) {
		this.subfolders = subfolders;
	}

	public Integer getStartYear() {
		return startYear;
	}

	public void setStartYear(Integer startYear) {
		this.startYear = startYear;
	}

	public Integer getEndYear() {
		return endYear;
	}

	public void setEndYear(Integer endYear) {
		this.endYear = endYear;
	}

	public boolean isDownloadNvd() {
		return downloadNvd;
	}

	public void setDownloadNvd(boolean downloadNvd) {
		this.downloadNvd = downloadNvd;
	}

	public Integer getnCoChangingThreshold() {
		return nCoChangingThreshold;
	}

	public void setnCoChangingThreshold(Integer nCoChangingThreshold) {
		this.nCoChangingThreshold = nCoChangingThreshold;
	}

	public String getPathToNeo4JDatabaseDirectory() {
		return pathToNeo4JInstallation + "/data/databases/joernIndex";
	}
	
	public String getPathToNeo4JInstallation() {
		return pathToNeo4JInstallation;
	}

	public void setPathToNeo4JInstallation(String pathToNeo4JInstallation) {
		this.pathToNeo4JInstallation = pathToNeo4JInstallation;
	}

	public boolean isLoadJoernNeo4JDatabase() {
		return loadJoernNeo4JDatabase;
	}

	public void setLoadJoernNeo4JDatabase(boolean loadJoernNeo4JDatabase) {
		this.loadJoernNeo4JDatabase = loadJoernNeo4JDatabase;
	}

	public boolean isStartNeo4J() {
		return startNeo4J;
	}

	public void setStartNeo4J(boolean startNeo4J) {
		this.startNeo4J = startNeo4J;
	}

	public String getLastCommitInPeriod() {
		return lastCommitInPeriod;
	}

	public void setLastCommitInPeriod(String lastCommitInPeriod) {
		this.lastCommitInPeriod = lastCommitInPeriod;
	}
	
}