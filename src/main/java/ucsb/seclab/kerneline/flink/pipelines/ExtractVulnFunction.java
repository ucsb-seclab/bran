package ucsb.seclab.kerneline.flink.pipelines;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.flink.api.common.accumulators.IntCounter;
import org.apache.flink.api.common.functions.RichFlatMapFunction;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.sources.NVD;
import ucsb.seclab.kerneline.utils.Utils;

public class ExtractVulnFunction extends RichFlatMapFunction<String, Function> {

	private static final long serialVersionUID = 1017661210567055436L;

	private final Logger logger = LoggerFactory.getLogger(ExtractVulnFunction.class);

	private NVD nvd;

	private IntCounter vulnFunCount = new IntCounter();

	private List<Function> vulnerableFunctions = new ArrayList<Function>();

	private String outputDir;
	private String localCodebase;
	private List<String> subfolders;
	private Integer nCoresPerHost;
	private Boolean extractFixedFunctions;

	@Override
	public void open(Configuration config) {
		getRuntimeContext().addAccumulator("vulnFunCount", this.vulnFunCount);
		this.localCodebase = this.localCodebase + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost;
	}

	@Override
	public void close() throws JsonGenerationException, JsonMappingException, IOException {
		Utils.executeBashScriptFromLocation(this.localCodebase, "git checkout master", new ArrayList<String>());
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(new File(
				outputDir + "/vulnFuns" + this.getRuntimeContext().getIndexOfThisSubtask() % nCoresPerHost + ".json"),
				this.vulnerableFunctions);
	}

	public ExtractVulnFunction(Map<String, Object> config) {
		this.nvd = new NVD((String) config.get("nvdRootDir"), (String) config.get("linuxCVEsMappingFile"), Integer.parseInt((String) config.get("startYear")),
				Integer.parseInt((String) config.get("endYear")), (Boolean) config.get("extractOnlyCVEsFromMappingFile"));
		this.outputDir = (String) config.get("outputDir");
		this.localCodebase = ((String) config.get("localCodebase"));
		this.subfolders = (List<String>) config.get("subfolders");
		this.nCoresPerHost = (Integer) config.get("nCoresPerHost");
		this.extractFixedFunctions = (Boolean) config.get("extractFixedFunctions");
	}

	@Override
	public void flatMap(String cve, Collector<Function> out) throws Exception {

		if (nvd.existsPatch(cve)) {

			String commitId = "";
			Set<String> affectedFunctionsNames = null;
			List<String> affectedFiles = null;
			String[] functionBodies = new String[2];
			Function tmpFun = null;

			// get the commit id that was fixing the current CVE
			commitId = nvd.getCvePatchId(cve);

			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] Found patch for CVE " + cve
					+ " in the considered time period: " + commitId);

			// extract files affected by the commit (performs git checkout!)
			affectedFiles = Utils.extractCommitAffectedFiles(commitId, this.localCodebase, this.outputDir + "/" + cve,
					this.subfolders);
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Number of file (in the considered subfolders) affected by commit " + commitId + ": "
					+ affectedFiles.size());

			// extract names of the functions that were affected by the commit
			affectedFunctionsNames = Utils.extractAffectedFunctionsNames(this.outputDir + "/" + cve + "/" + commitId,
					affectedFiles);
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
					+ "] Number of functions (in the considered subfolders) affected by commit " + commitId + ": "
					+ affectedFunctionsNames.size());

			// extract the functions that were affected by the commit and insert all the
			// extracted functions in the current CVE dataset entry

			for (String functionName : affectedFunctionsNames) {
				tmpFun = new Function();
				tmpFun.setName(functionName);
				tmpFun.setFixingCommit(commitId);
				tmpFun.setFixingCve(cve);
				tmpFun.setSha(DigestUtils.sha256Hex(commitId + functionName));
				tmpFun.setIsVulnerable(true);

				logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
						+ "]Extracting body of function " + tmpFun.getName() + " at commit " + commitId);
				functionBodies = Utils.extractVulnerableFunctionBody(this.outputDir, cve, commitId, tmpFun);

				if (functionBodies != null && functionBodies[0] != null && tmpFun.getFile().endsWith(".c")) {
					tmpFun.setId(tmpFun.getName() + "_"
							+ tmpFun.getFileRelative().replaceAll("/", "%").replaceAll("\\.c", "") + "_" + commitId
							+ "_" + cve);

					if (this.extractFixedFunctions) {
						tmpFun.setBody(functionBodies[1]);
					} else {
						tmpFun.setBody(functionBodies[0]);
					}
					this.vulnerableFunctions.add(tmpFun);
					this.vulnFunCount.add(1);
				} else {
					logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask()
							+ "] Dropping vulnerable functions because of empty extracted body: " + tmpFun.getName()
							+ " " + tmpFun.getFileRelative() + " " + tmpFun.getFixingCve() + " "
							+ tmpFun.getFixingCommit());
				}

			}

		} else {
			logger.info("[Worker " + this.getRuntimeContext().getIndexOfThisSubtask() + "] " + cve
					+ " does not have a corresponding patch reported in the NVD.");
		}
	}
}
