package ucsb.seclab.kerneline.sources;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;

import org.apache.flink.streaming.api.datastream.DataStreamSource;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;

import ucsb.seclab.kerneline.flink.pipelines.ExtractCVEHistory;
import ucsb.seclab.kerneline.model.CVEHistory;
import ucsb.seclab.kerneline.model.Revision;

public class BreakFixCVEMapping {

	public static Set<CVEHistory> getInputData(String pathToMappingFile) throws FileNotFoundException, IOException {
		Set<CVEHistory> toReturn = new HashSet<CVEHistory>();
		CVEHistory tmp = null;
		BufferedReader br = new BufferedReader(new FileReader(pathToMappingFile));
		String line;
		String[] splits;
		Revision tmpBreaking = null;
		Revision tmpFixing = null;
		while ((line = br.readLine()) != null) {
			splits = line.split(":");
			if (splits[1].split("-")[0].replaceAll("\\s+", "").matches("[0-9a-f]{40}")) {
				if (splits[1].split("-")[1].replaceAll("\\s+", "").split("\\(")[0].matches("[0-9a-f]{40}")) {
					tmp = new CVEHistory();
					tmp.setCveId(splits[0]);
					tmpBreaking = new Revision();
					tmpFixing = new Revision();
					tmpBreaking.setCommit(splits[1].split("-")[0].replaceAll("\\s+", ""));
					tmpFixing.setCommit(splits[1].split("-")[1].replaceAll("\\s+", "").split("\\(")[0]);
					tmp.setBreakingRevision(tmpBreaking);
					tmp.setFixingRevision(tmpFixing);
					toReturn.add(tmp);
				}
			}
		}

		br.close();
		return toReturn;
	}

	public static void main(String[] args) throws Exception {

		Map<String, Object> config = new HashMap<String, Object>();

		config.put("outputDir", "/home/utente/ucsb-workspace/kerneline/results");
		config.put("localCodebase", "/home/utente/ucsb/project-stuff/linux");
		config.put("subfolders", new ArrayList<String>() {
			{
				add("kernel");
				add("drivers");
				add("arch");
				add("fs");
				add("net");
				add("init");
				add("block");
				add("certs");
				add("crypto");
				add("ipc");
				add("security");
				add("sound");
				add("tools");
			}
		});
		config.put("nCoresPerHost", 4);

		StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();

		env.setParallelism((Integer) config.get("nCoresPerHost"));

		DataStreamSource<CVEHistory> source = env
				.fromCollection(getInputData("/home/utente/ucsb-workspace/kerneline/cve-linux-break-fix.txt"));
		source.name("source");

		source.flatMap(new ExtractCVEHistory(config)).returns(CVEHistory.class).name("process");

		env.execute();
	}

}
