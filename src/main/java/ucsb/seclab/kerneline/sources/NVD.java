package ucsb.seclab.kerneline.sources;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.model.CVEHistory;
import ucsb.seclab.kerneline.model.Revision;
import ucsb.seclab.kerneline.utils.Utils;

public class NVD  implements Serializable{

	private static final long serialVersionUID = -1582851027474405289L;

	private Map<String, String> commitPerCves;

	private static final Logger logger = LoggerFactory.getLogger(NVD.class);

	private Integer currentYear;

	private String nvdRootDir;
	
	public static void main(String[] args) {
		NVD n = new NVD("/home/utente/ucsb-workspace/kerneline/nvd", "/home/utente/ucsb-workspace/kerneline/cve-linux-break-fix.txt", 2006, 2018, true);
		for(String cve: n.commitPerCves.keySet()) {
			System.out.println(cve + " " + n.commitPerCves.get(cve));
		}
	}
		
	public NVD(String nvdRootDir, String linuxCVEsMappingFile, Integer startYear, Integer endYear, Boolean extractOnlyCVEsFromMappingFile) {
		this.nvdRootDir = nvdRootDir;

		Map<String, String> cvesMappingFromNvd = new HashMap<String, String>();
		Map<String, String> cvesMappingFromCustomMapping = new HashMap<String, String>();
		
		for (int i = startYear; i <= endYear; i++) {
			this.currentYear = i;
			loadCurrent();

			Iterator<JsonNode> iter = loadCurrent().iterator();
			JsonNode currentNVDYearCves = null;

			while (iter.hasNext()) {
				JsonNode year = iter.next();

				currentNVDYearCves = year.get("CVE_Items");

				int counter1 = 0;
				while (currentNVDYearCves.get(counter1) != null) {
					if (currentNVDYearCves.get(counter1).get("cve").get("CVE_data_meta").get("ID").asText()
							.contains("CVE-")) {
						JsonNode cve = currentNVDYearCves.get(counter1).get("cve").get("references")
								.get("reference_data");

						int counter2 = 0;

						while (cve.get(counter2) != null) {
							if (cve.get(counter2).get("url").asText().contains("commit")) {
								String[] urlSplits = cve.get(counter2).get("url").asText().split("/");
								String[] patchSplits = urlSplits[urlSplits.length - 1].split("=");
								cvesMappingFromNvd.put(currentNVDYearCves.get(counter1).get("cve").get("CVE_data_meta")
										.get("ID").asText(), patchSplits[patchSplits.length - 1]);
							}

							counter2 = counter2 + 1;
						}

					}
					counter1 = counter1 + 1;
				}
			}
		}		
		
		BufferedReader br;
		try {
			br = new BufferedReader(new FileReader(linuxCVEsMappingFile));
		    String line;
		    String[] splits;
		    while ((line = br.readLine()) != null) {
		    	splits = line.split(":");	 
		    	if(splits[1].split("-").length > 1 && splits[1].split("-")[1].replaceAll("\\s+","").split("\\(").length >= 1) {
					if(splits[1].split("-")[1].replaceAll("\\s+","").split("\\(")[0].matches("[0-9a-f]{40}")) {
						if(!cvesMappingFromNvd.containsKey(splits[0])) {
					    	cvesMappingFromCustomMapping.put(splits[0], splits[1].split("-")[1].replaceAll("\\s+","").split("\\(")[0]);
						}
					}	    		
		    	}
		    }
		    
		    br.close();
		} catch (FileNotFoundException e) {
			logger.error("CVEs mapping file not found.");
			e.printStackTrace();
		} catch (IOException e) {
			logger.error("Problems reading the CVEs mapping file.");
			e.printStackTrace();
		}
				
		if(extractOnlyCVEsFromMappingFile) {
			this.commitPerCves = new HashMap<String, String>(cvesMappingFromCustomMapping);
		} else {
			this.commitPerCves = new HashMap<String, String>(cvesMappingFromNvd);
			this.commitPerCves.putAll(cvesMappingFromCustomMapping);
		}

	}
	
	private List<JsonNode> loadCurrent() {

		ObjectMapper mapper = new ObjectMapper();

		List<JsonNode> cached;
		try {

			JsonNode currentYear = mapper.readTree(
					Utils.readFile(nvdRootDir + "/nvdcve-1.0-" + this.currentYear + ".json", Charset.defaultCharset()));

			cached = new ArrayList<JsonNode>() {
				private static final long serialVersionUID = 6293373747368602801L;
				{
					add(currentYear);
				}
			};
			
			return cached;
		} catch (IOException e) {
			logger.error("Error loading one of the expected .json files from NVD containing kernel's vulnerabilities."
					+ " Please check all files from 2002 to 2018 are available in the provided NVD root directory.");
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
	}

	public String getCvePatchId(String cveId) {

		return this.commitPerCves.get(cveId);
	}

	public boolean existsPatch(String cveId) {

		if (this.getCvePatchId(cveId) != null) {

			String patch = this.getCvePatchId(cveId);
			String[] patchSplits = patch.split("=");
			String commitId = patchSplits[patchSplits.length - 1];

			// check the commitId is valid
			if (!(commitId.contains(".") || commitId.contains("-")) && commitId.length() >= 8) {
				return true;
			} else {
				return false;
			}

		} else {
			return false;
		}
	}

}
