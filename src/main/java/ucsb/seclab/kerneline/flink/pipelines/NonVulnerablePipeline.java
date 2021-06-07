package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.util.List;

import org.antlr.v4.runtime.misc.Utils;
import org.apache.flink.api.common.JobExecutionResult;
import org.apache.flink.core.fs.FileSystem.WriteMode;
import org.apache.flink.streaming.api.datastream.DataStreamSource;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.model.Function;

public class NonVulnerablePipeline {

	private static final Logger logger = LoggerFactory.getLogger(NonVulnerablePipeline.class);

	public void extractNonVulnFunctions(List<String> functions, String lastCommitInPeriod, String localCodebase,
			String outputDir, Integer nPhisicalHosts, Integer nCoresPerHost, String neo4jUrl, Integer neo4jPort,
			String neo4jUser, String neo4jPass, Integer nCoChangingThreshold, String githubRepoName, String githubUser,
			String githubPassword) throws Exception {

		StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
		env.setParallelism(nPhisicalHosts * nCoresPerHost);

		DataStreamSource<String> input = env.fromCollection(functions);
		input.name("AllFunctionsSource");
		input.flatMap(new ProcessNonVulnFunction(lastCommitInPeriod, localCodebase, outputDir, neo4jUrl, neo4jPort,
				neo4jUser, neo4jPass, nCoChangingThreshold, nCoresPerHost, githubRepoName, githubUser, githubPassword))
				.returns(Function.class).name("ProcessNonVulnFunction").map(x -> x.toString())
				.writeAsText(outputDir + "/non-vuln.csv", WriteMode.OVERWRITE).setParallelism(1)
				.name("NonVulnOutputWriter");

		JobExecutionResult result = env.execute();

		Integer nonVulnFunCount = result.getAccumulatorResult("nonVulnFunCount");
		logger.info("Number of extracted non vulnerable functions: " + nonVulnFunCount);

	}
}
