package ucsb.seclab.kerneline.sources;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ucsb.seclab.kerneline.utils.Utils;

public class CVEs {

	private Map<Integer, List<String>> cveIdsPerYear;

	private static final Logger logger = LoggerFactory.getLogger(CVEs.class);

	public CVEs(Path cvesLocation, Integer startYear, Integer endYear) {
		this.cveIdsPerYear = new HashMap<Integer, List<String>>();
		this.init(cvesLocation, startYear, endYear);
	}

	private void init(Path cvesLocation, Integer startYear, Integer endYear) {

		String[] cve = null;
		String line = "";
		Integer year = null;
		List<String> tmpToAdd = null;

		try (BufferedReader br = new BufferedReader(new FileReader(cvesLocation.toString()))) {

			br.readLine();
			line = br.readLine();
			while (line != null) {
				cve = line.split(",");
				year = Integer.parseInt(cve[1].split("-")[1]);

				if (year >= startYear && year <= endYear) {
					if (this.cveIdsPerYear.containsKey(year)) {
						this.cveIdsPerYear.get(year).add(cve[1]);
					} else {
						tmpToAdd = new ArrayList<String>();
						tmpToAdd.add(cve[1]);
						this.cveIdsPerYear.put(year, tmpToAdd);
					}
				} else {
					logger.info(cve[1] + " is not within the considered time period.");
				}
				line = br.readLine();
			}

		} catch (IOException e) {
			logger.error("IOException while the reading of the kernel CVEs from json file.");
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
	}

	public List<String> getCVEs(Integer year) {
		return this.cveIdsPerYear.get(year);
	}

}
