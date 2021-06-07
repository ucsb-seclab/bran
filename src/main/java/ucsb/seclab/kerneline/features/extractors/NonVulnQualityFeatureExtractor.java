package ucsb.seclab.kerneline.features.extractors;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ucsb.seclab.kerneline.joern.JoernNeo4JDriver;
import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.Utils;

public class NonVulnQualityFeatureExtractor extends QualityFeatureExtractor {

	private static final Logger logger = LoggerFactory.getLogger(NonVulnQualityFeatureExtractor.class);

	public NonVulnQualityFeatureExtractor(String pathToCodebase, String pathToResultFolder) {
		super(pathToCodebase, pathToResultFolder);
	}

	public Integer getModuleLoc(Function f) {
		Integer toReturn = null;

		// compute the loc of the retrieved file
		try {
			toReturn = this.getLoc(Utils.readFile(this.pathToCodebase + "/" + f.getFileRelative(), Charset.defaultCharset()));
		} catch (IOException e) {
			logger.info("The file retrieved from joern " + f.getFileRelative() + " for the function " + f.getName()
					+ " is not available in the checkout codebase");
		}

		return toReturn;
	}

	public Double getModuleMcCabeComplexity(Function f) throws IOException, InterruptedException {
		Double toReturn = 0.0;

		// running pmccabe over the retrieved file
		File tempScript = File.createTempFile("script", null);

		Writer streamWriter;
		streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

		PrintWriter printWriter = new PrintWriter(streamWriter);

		printWriter = new PrintWriter(streamWriter);

		printWriter.println("#!/bin/bash");
		printWriter.println("pmccabe " + this.pathToCodebase + "/" + f.getFileRelative());

		printWriter.close();

		ProcessBuilder pb = new ProcessBuilder("bash", tempScript.toString());
		// pb.inheritIO();
		Process process = pb.start();
		// process.waitFor();

		BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		String line = null;
		while ((line = reader.readLine()) != null) {
			toReturn = toReturn + Double.parseDouble(line.split("	")[1]);
		}

		tempScript.delete();

		return toReturn;
	}

}
