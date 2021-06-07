package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.flink.core.fs.FileSystem.WriteMode;
import org.apache.flink.streaming.api.datastream.DataStreamSource;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ucsb.seclab.kerneline.model.Function;

import org.antlr.v4.runtime.misc.Utils;
import org.apache.flink.api.common.JobExecutionResult;
import org.apache.flink.api.common.typeinfo.TypeHint;
import org.apache.flink.api.common.typeinfo.TypeInformation;
import org.apache.flink.api.java.tuple.Tuple2;

public class VulnerablePipeline {

	private static final Logger logger = LoggerFactory.getLogger(VulnerablePipeline.class);

	public Integer extractVulnFunctions(List<String> cves, String nvdRootDir, String linuxCVEsMappingFile,
			Integer startYear, Integer endYear, String outputDir, String localCodebase, List<String> subfolders,
			Integer nPhisicalHosts, Integer nCoresPerHost, String pathToNeo4JInstallation,
			String pathToNeo4JDatabaseDirectory, Integer nCoChangingThreshold, String githubRepoName,
			Boolean extractFixedFunctions, Boolean extractOnlyCVEsFromMappingFile, String githubUser, String githubPassword) throws Exception {

		Map<String, Object> config = new HashMap<String, Object>();
		Double runtime = 0.0;

		config.put("nvdRootDir", nvdRootDir);
		config.put("startYear", startYear.toString());
		config.put("endYear", endYear.toString());
		config.put("outputDir", outputDir);
		config.put("localCodebase", localCodebase);
		config.put("subfolders", subfolders);
		config.put("pathToNeo4JDatabaseDirectory", pathToNeo4JDatabaseDirectory);
		config.put("pathToNeo4JInstallation", pathToNeo4JInstallation);
		config.put("nCoChangingThreshold", nCoChangingThreshold);
		config.put("nPhisicalHosts", nPhisicalHosts);
		config.put("githubRepoName", githubRepoName);
		config.put("nCoresPerHost", nCoresPerHost);
		config.put("extractFixedFunctions", extractFixedFunctions);
		config.put("linuxCVEsMappingFile", linuxCVEsMappingFile);
		config.put("extractOnlyCVEsFromMappingFile", extractOnlyCVEsFromMappingFile);
		config.put("githubUser", githubUser);
		config.put("githubPassword", githubPassword);

		StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
		env.setParallelism(nPhisicalHosts * nCoresPerHost);

		//
		DataStreamSource<String> cvesStream = env.fromCollection(cves);
		cvesStream.name("CVEsSource");
		TypeInformation<List<Function>> info = TypeInformation.of(new TypeHint<List<Function>>() {
		});

		cvesStream.flatMap(new ExtractVulnFunction(config)).returns(Function.class).name("ExtractVulnFunction");

		JobExecutionResult result = env.execute();
		runtime = runtime + result.getNetRuntime();

		Integer vulnFunCount = result.getAccumulatorResult("vulnFunCount");

		List<String> startCommands = new ArrayList<String>();

		for (int i = 0; i < nPhisicalHosts * nCoresPerHost; i++) {
			startCommands.add("START");
		}

		DataStreamSource<String> characterizeVulnFunsStartCommands = env.fromCollection(startCommands);
		characterizeVulnFunsStartCommands.name("CharacterizeVulnFunsStartCommands");

		characterizeVulnFunsStartCommands.flatMap(new CharacterizeVulnFunction(config)).returns(Function.class)
				.name("CharacterizeVulnFunction")
				.writeAsText(config.get("outputDir") + "/vuln.csv", WriteMode.OVERWRITE).setParallelism(1)
				.name("VulnOutputWriter");

		result = env.execute();
		runtime = runtime + result.getNetRuntime();

		//////////////////////////////////////////////////
		startCommands = new ArrayList<String>();

		for (int i = 0; i < nPhisicalHosts * nCoresPerHost; i++) {
			startCommands.add("START");
		}

		DataStreamSource<String> extractVulnFunAstsStartCommands = env.fromCollection(startCommands);
		extractVulnFunAstsStartCommands.name("ExtractVulnFunAstStartCommands");

		extractVulnFunAstsStartCommands.flatMap(new ExtractVulnFunctionAst(config)).returns(Function.class)
				.name("ExtractVulnFunctionAst");

		result = env.execute();
		runtime = runtime + result.getNetRuntime();

		logger.info("Vulnerable functions extraction execution time: " + runtime);

		return vulnFunCount;

	}

}
