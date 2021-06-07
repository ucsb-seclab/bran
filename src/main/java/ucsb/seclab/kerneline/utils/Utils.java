package ucsb.seclab.kerneline.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FilenameUtils;
import org.neo4j.kernel.impl.nioneo.store.SchemaRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.safepatch.flowres.FunctionMap;
import ucsb.seclab.kerneline.model.Function;

public class Utils {

	private static final Logger logger = LoggerFactory.getLogger(Utils.class);

	public static void writeFile(String path, String content) throws IOException {
		FileOutputStream outputStream = new FileOutputStream(path);
		byte[] strToBytes = content.getBytes();
		outputStream.write(strToBytes);
		outputStream.close();
	}

	public static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	public static void unzipFile(String pathToFile, String outputDir) throws IOException {
		byte[] buffer = new byte[1024];
		ZipInputStream zis = new ZipInputStream(new FileInputStream(pathToFile));
		ZipEntry zipEntry = zis.getNextEntry();
		while (zipEntry != null) {
			String fileName = zipEntry.getName();
			File newFile = new File(fileName);
			FileOutputStream fos = new FileOutputStream(outputDir + "/" + newFile);
			int len;
			while ((len = zis.read(buffer)) > 0) {
				fos.write(buffer, 0, len);
			}
			fos.close();
			zipEntry = zis.getNextEntry();
		}
		zis.closeEntry();
		zis.close();
	}

	public static String executeBashScript(String script, List<String> arguments) {
		Process process = null;
		ProcessBuilder pb = null;
		BufferedReader reader = null;
		StringBuilder builder = null;
		String line = null;
		File tempScript = null;
		Writer streamWriter = null;
		PrintWriter printWriter = null;

		try {

			builder = new StringBuilder();

			tempScript = File.createTempFile("script", null);

			streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));
			printWriter = new PrintWriter(streamWriter);

			printWriter.println(script);

			printWriter.close();

			List<String> completeArgs = new ArrayList<String>();
			completeArgs.add("bash");
			completeArgs.add(tempScript.toString());
			completeArgs.addAll(arguments);

			pb = new ProcessBuilder(completeArgs);

			process = pb.start();

			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			while ((line = reader.readLine()) != null) {
				builder.append(line);
				builder.append(System.getProperty("line.separator"));
			}
			reader.close();

			return builder.toString();

		} catch (IOException e) {
			throw new RuntimeException(e.getMessage(), e.getCause());
		} finally {
			tempScript.delete();
		}
	}

	public static String executeBashScriptFromLocation(String location, String script, List<String> arguments) {

		String scriptToExecute = "#!/bin/sh" + "\n" + "cd " + location + "\n" + script;
		return executeBashScript(scriptToExecute, arguments);

	}

	public static String extractFunctionBodyFromFile(String filepath, String functionName) {

		Process process = null;
		ProcessBuilder pb = null;
		BufferedReader reader = null;
		StringBuilder builder = null;
		String functionLine = null;
		File tempScript = null;
		Writer streamWriter = null;
		PrintWriter printWriter = null;

		try {

			builder = new StringBuilder();

			tempScript = File.createTempFile("script", null);

			streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));
			printWriter = new PrintWriter(streamWriter);

			printWriter.println("#!/bin/sh");
			printWriter.println("indent -st -orig \"$1\" | awk '");
			printWriter.println("BEGIN { state = 0; last = \"\"; }");
			printWriter.println("$0 ~ /^'$2'\\(/ { print last; state = 1; }");
			printWriter.println("        { if (state == 1) print; }");
			printWriter.println("$0 ~ /^}/ { if (state) state = 2; }");
			printWriter.println("        { last = $0; }");
			printWriter.println("'");

			printWriter.close();
			pb = new ProcessBuilder("bash", tempScript.toString(), filepath, functionName);

			process = pb.start();
			// process.waitFor();

			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			while ((functionLine = reader.readLine()) != null) {
				builder.append(functionLine);
				builder.append(System.getProperty("line.separator"));
			}

			if (!builder.toString().isEmpty()) {
				return builder.toString();
			} else {
				return null;
			}
		} catch (IOException e) {
			throw new RuntimeException(e.getMessage(), e.getCause());
		} finally {
			tempScript.delete();
		}
	}

	@SuppressWarnings("deprecation")
	public static Set<String> extractAffectedFunctionsNames(String pathToNewOldFolders,
		List<String> affectedFiles) {
		List<FunctionMap> funs = new ArrayList<FunctionMap>();
		List<FunctionMap> tmp = null; 
		Set<String> toReturn = new HashSet<String>();
		for (String file : affectedFiles) {
			FunctionDiffCheck fdc =  new FunctionDiffCheck();
			tmp = fdc.getDiffFunctions(
					pathToNewOldFolders + "/old_files/" + file.split("/")[file.split("/").length - 1],
					pathToNewOldFolders + "/new_files/" + file.split("/")[file.split("/").length - 1]);
			
			if(tmp != null) {
				funs.addAll(tmp);
			}
		}

		for (FunctionMap f : funs) {
			toReturn.add(f.getOldFunction().name.getCompleteCodeContent());
		}
		return toReturn;
	}

	public static Boolean isValidCommit(String pathToCodebase, String commitId) {
		String n = Utils.executeBashScriptFromLocation(pathToCodebase,
				"git diff " + commitId + "^.." + commitId + " --name-only | wc -l", new ArrayList<String>());
		try {
			return !commitId.equals("1da177e4c3f41524e886b7f1b8a0c1fc7321cac2")
					&& (NumberFormat.getInstance().parse(n).intValue() < 500);
		} catch (ParseException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static List<String> extractCommitAffectedFilesNames(String commitId, String pathToCodebase) {

		try {
			List<String> fileNames = new ArrayList<String>();
			String fileName;
			BufferedReader reader = null;

			File tempScript = File.createTempFile("script", null);

			Writer streamWriter;
			streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

			PrintWriter printWriter = new PrintWriter(streamWriter);

			printWriter.println("#!/bin/bash");
			printWriter.println("cd " + pathToCodebase);

			printWriter.println("git diff-tree --no-commit-id --name-only -r " + commitId);
			printWriter.close();

			ProcessBuilder pb = new ProcessBuilder("bash", tempScript.toString());
			Process process = pb.start();

			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			while ((fileName = reader.readLine()) != null) {
				fileNames.add(fileName);
			}

			tempScript.delete();

			return fileNames;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static List<String> extractCommitAffectedFiles(String commitId, String pathToCodebase, String outputDir,
			List<String> subfolders) {
		try {

			File tempScript = File.createTempFile("script", null);

			Writer streamWriter;
			streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

			PrintWriter printWriter = new PrintWriter(streamWriter);

			printWriter.println("#!/bin/bash");
			printWriter.println("cd " + pathToCodebase);

			printWriter.println("mkdir " + outputDir);
			printWriter.println("mkdir " + outputDir + "/" + commitId);
			printWriter.println("mkdir " + outputDir + "/" + commitId + "/old_files");
			printWriter.println("mkdir " + outputDir + "/" + commitId + "/new_files");

			printWriter.println("git diff-tree --no-commit-id --name-only -r " + commitId + " > " + outputDir + "/"
					+ commitId + "/affected-files.txt");
			printWriter.close();

			ProcessBuilder pb = new ProcessBuilder("bash", tempScript.toString());
			Process process = pb.start();
			process.waitFor();
			tempScript.delete();

			File f = new File(outputDir + "/" + commitId + "/affected-files.txt");
			if (f.exists() && !f.isDirectory()) {
				Utils.executeBashScriptFromLocation(pathToCodebase, "git checkout " + commitId + "^",
						new ArrayList<String>());

				if (subfolders != null && !subfolders.isEmpty()) {
					for (String subfolder : subfolders) {
						tempScript = File.createTempFile("script", null);

						streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

						printWriter = new PrintWriter(streamWriter);

						printWriter.println("#!/bin/bash");
						printWriter.println("cd " + pathToCodebase);

						printWriter.println("if [ -f " + outputDir + "/" + commitId + "/affected-files.txt ]; then\n"
								+ "while read p; do\n" + "if [[ $p = \"" + subfolder
								+ "\"* ]]; then\n" + "  cp " + pathToCodebase + "/$p " + outputDir + "/" + commitId
								+ "/old_files/" + "\n" + "fi\n" + "done<" + outputDir + "/" + commitId
								+ "/affected-files.txt\n" + "fi");
						printWriter.close();

						pb = new ProcessBuilder("bash", tempScript.toString());
						process = pb.start();
						Thread.sleep(2000);
						tempScript.delete();
					}
				} else {
					tempScript = File.createTempFile("script", null);

					streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

					printWriter = new PrintWriter(streamWriter);

					printWriter.println("#!/bin/bash");
					printWriter.println("cd " + pathToCodebase);

					printWriter.println("if [ -f " + outputDir + "/" + commitId + "/affected-files.txt ]; then\n"
							+ "while read p; do\n" + "  cp " + pathToCodebase + "/$p " + outputDir + "/" + commitId
							+ "/old_files/" + "\n" + "done<" + outputDir + "/" + commitId + "/affected-files.txt\n"
							+ "fi");
					printWriter.close();

					pb = new ProcessBuilder("bash", tempScript.toString());
					process = pb.start();
					Thread.sleep(2000);
					tempScript.delete();
				}

				Utils.executeBashScriptFromLocation(pathToCodebase, "git checkout " + commitId,
						new ArrayList<String>());

				if (subfolders != null && !subfolders.isEmpty()) {
					for (String subfolder : subfolders) {
						tempScript = File.createTempFile("script", null);

						streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

						printWriter = new PrintWriter(streamWriter);

						printWriter.println("#!/bin/bash");
						printWriter.println("cd " + pathToCodebase);

						printWriter.println("if [ -f " + outputDir + "/" + commitId + "/affected-files.txt ]; then\n"
								+ "while read p; do\n" + "if [[ $p = \"" + subfolder
								+ "\"* ]]; then\n" + "  cp " + pathToCodebase + "/$p " + outputDir + "/" + commitId
								+ "/new_files/" + "\n" + "fi\n" + "done<" + outputDir + "/" + commitId
								+ "/affected-files.txt\n" + "fi");
						printWriter.close();

						pb = new ProcessBuilder("bash", tempScript.toString());
						process = pb.start();
						Thread.sleep(2000);
						tempScript.delete();
					}
				} else {
					tempScript = File.createTempFile("script", null);

					streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));

					printWriter = new PrintWriter(streamWriter);

					printWriter.println("#!/bin/bash");
					printWriter.println("cd " + pathToCodebase);

					printWriter.println("if [ -f " + outputDir + "/" + commitId + "/affected-files.txt ]; then\n"
							+ "while read p; do\n" + "  cp " + pathToCodebase + "/$p " + outputDir + "/" + commitId
							+ "/new_files/" + "\n" + "done<" + outputDir + "/" + commitId + "/affected-files.txt\n"
							+ "fi");
					printWriter.close();

					pb = new ProcessBuilder("bash", tempScript.toString());
					process = pb.start();
					Thread.sleep(2000);
					tempScript.delete();
				}

				String[] files = Utils
						.readFile(outputDir + "/" + commitId + "/affected-files.txt", Charset.defaultCharset())
						.split("\n");

				List<String> toReturn = new ArrayList<String>();

				for (int i = 0; i < files.length; i++) {
					if (!files[i].isEmpty() && !files[i].equals("")) {
						if(subfolders != null) {
							boolean found = false;
							for(String subfolder: subfolders) {
								if(files[i].startsWith(subfolder)) {
									found = true;
								}
							}
							
							if(found) {
								toReturn.add(files[i]);
							}
						} else {
							toReturn.add(files[i]);
						}
					}
				}

				return toReturn;
			} else {

				return new ArrayList<String>();
			}

		} catch (IOException e) {
			logger.error("There were problems creating or running the temp script for extracting CVEs affected files.");
			e.printStackTrace();
			throw new RuntimeException(e.getMessage(), e.getCause());
		} catch (InterruptedException e) {
			logger.error("Execution of script for extracting CVEs affected files has been interrupted.");
			e.printStackTrace();
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
	}

	public static String[] extractVulnerableFunctionBody(String outputDir, String cve, String commitId, Function function) {
		String [] toReturn = new String[2];
		Process process = null;
		ProcessBuilder pb = null;
		BufferedReader reader = null;
		StringBuilder builder = new StringBuilder();
		String functionLine = null;
		File tempScript = null;
		Writer streamWriter = null;
		PrintWriter printWriter = null;
		String tmpFilePath;

		File oldDir = new File(outputDir + "/" + cve + "/" + commitId + "/old_files" );
		File newDir = new File(outputDir + "/" + cve + "/" + commitId + "/new_files" );

		File[] directoryListing = oldDir.listFiles();
		if (directoryListing != null) {
			for (File child : directoryListing) {
				if (!FilenameUtils.getExtension(child.getAbsolutePath()).equals("txt")) {
					try {
						tempScript = File.createTempFile("script", null);

						streamWriter = new OutputStreamWriter(new FileOutputStream(tempScript));
						printWriter = new PrintWriter(streamWriter);

						printWriter.println("#!/bin/sh");
						printWriter.println("indent -st -orig \"$1\" | awk '");
						printWriter.println("BEGIN { state = 0; last = \"\"; }");
						printWriter.println("$0 ~ /^'$2'\\(/ { print last; state = 1; }");
						printWriter.println("        { if (state == 1) print; }");
						printWriter.println("$0 ~ /^}/ { if (state) state = 2; }");
						printWriter.println("        { last = $0; }");
						printWriter.println("'");

						printWriter.close();

						pb = new ProcessBuilder("bash", tempScript.toString(), child.getAbsolutePath(),
								function.getName());
						process = pb.start();

						reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
						while ((functionLine = reader.readLine()) != null) {
							builder.append(functionLine);
							builder.append(System.getProperty("line.separator"));
						}

						if (!builder.toString().isEmpty()) {

							tmpFilePath = Utils.executeBashScriptFromLocation(outputDir + "/" + cve + "/" + commitId,
									"grep " + child.getName() + " affected-files.txt", new ArrayList<String>());

							function.setFile(tmpFilePath.substring(0, tmpFilePath.length() - 1));
							function.setFileRelative(tmpFilePath.substring(0, tmpFilePath.length() - 1));
							toReturn[0] = builder.toString();
							
							pb = new ProcessBuilder("bash", tempScript.toString(), newDir.getAbsolutePath() + "/" + child.getName(),
									function.getName());
							process = pb.start();

							builder = new StringBuilder();
							reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
							while ((functionLine = reader.readLine()) != null) {
								builder.append(functionLine);
								builder.append(System.getProperty("line.separator"));
							}
							
							if(!builder.toString().isEmpty()) {
								toReturn[1] = builder.toString();
							}
							
							return toReturn;

						}
					} catch (IOException e) {
						throw new RuntimeException(e.getMessage(), e.getCause());
					} finally {
						tempScript.delete();
					}

				}
			}
		}

		return null;
	}

	public static List<String> getAffectedFilesNames(String commitId, String localKernelRepo) {

		return Arrays.asList(Utils
				.executeBashScriptFromLocation(localKernelRepo,
						"git diff-tree --no-commit-id --name-only -r " + commitId, new ArrayList<String>())
				.split("\n"));

	}

}
