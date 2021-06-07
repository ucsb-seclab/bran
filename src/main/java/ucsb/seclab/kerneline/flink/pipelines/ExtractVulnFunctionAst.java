package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.flink.api.common.functions.RichFlatMapFunction;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.util.Collector;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.exceptions.ServiceUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import fileWalker.OrderedWalker;
import fileWalker.SourceFileWalker;
import outputModules.neo4j.Neo4JIndexer;
import tools.index.Indexer;
import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public class ExtractVulnFunctionAst extends RichFlatMapFunction<String, Function> {

	private static final long serialVersionUID = -3201913006419874039L;

	private static final Logger logger = LoggerFactory.getLogger(ExtractVulnFunctionAst.class);

	private String outputDir;

	private String pathToNeo4JInstallation;

	private Integer nCoresPerHost;

	private List<Function> vulnerableFunctions;

	public ExtractVulnFunctionAst(Map<String, Object> config) {
		this.outputDir = (String) config.get("outputDir");
		this.pathToNeo4JInstallation = (String) config.get("pathToNeo4JInstallation") + "_vuln";
		this.nCoresPerHost = (Integer) config.get("nCoresPerHost");
	}

	@Override
	public void open(Configuration config) {
		if (this.pingNeo4J()) {
			this.stopNeo4J();
		}

		if (getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost == 1) {
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
				List<Record> indexes = joern.sendQuery("CALL db.indexes");

				for (Record idx : indexes) {
					if (idx.get("description").toString().contains("CFGEntryNode")
							&& idx.get("state").toString().contains("ONLINE")) {
						indexesReady = true;
					}
				}
			}

		}
	}
	
	@Override
	public void close() throws JsonGenerationException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(new File(outputDir + "/vulnFuns" +  this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"), this.vulnerableFunctions);
	}

	@Override
	public void flatMap(String command, Collector<Function> out) throws Exception {
		if (command.equals("START")) {
			ObjectMapper mapper = new ObjectMapper();
			vulnerableFunctions = mapper
					.readValue(
							new File(outputDir + "/vulnFuns"
									+ this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"),
							new TypeReference<List<Function>>() {
							});
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Getting the ASTs of " + vulnerableFunctions.size()
					+ " vulnerable functions.");
			if (vulnerableFunctions.size() > 0) {
				for (Function f : vulnerableFunctions) {
					// GET THE AST FOR THE VULNERABLE VERSION OF f AND ASSIGN IT TO f
					f.setAst(JoernNeo4JDriver.getInstance().getAst(f.getName(), this.outputDir + "/word2vec-corpus/" + f.getId() + ".c"));
				}
			}
		}
	}

	private void generateJoernDatabase() {
		this.dropPreviousDatabase();
		SourceFileWalker sourceFileWalker = new OrderedWalker();

		Indexer indexer = new Neo4JIndexer();
		indexer.setOutputDir(this.pathToNeo4JInstallation + "/data/databases/joernIndex");
		indexer.initialize();
		sourceFileWalker.addListener(indexer);
		try {

			String[] dirToWalk = new String[1];
			dirToWalk[0] = this.outputDir + "/word2vec-corpus";
			sourceFileWalker.walk(dirToWalk);

		} catch (IOException err) {
			logger.error("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Error walking source files: " + err.getMessage());
		} finally {
			indexer.shutdown();
		}
	}
	
	private void dropPreviousDatabase() {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Dropping previous Neo4J database.");
		Utils.executeBashScriptFromLocation(this.pathToNeo4JInstallation, "rm -rf data/databases/joernIndex", new ArrayList<String>());
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

	private void stopNeo4J() {
		logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Stopping local Neo4J instance.");
		Utils.executeBashScriptFromLocation(this.pathToNeo4JInstallation, "./bin/neo4j stop", new ArrayList<String>());
	}

	public boolean pingNeo4J() {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress("localhost", 7688), 10000);
			return true;
		} catch (IOException e) {
			return false; // Either timeout or unreachable or failed DNS lookup.
		}
	}

}
