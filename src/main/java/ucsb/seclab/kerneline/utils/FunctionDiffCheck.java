package ucsb.seclab.kerneline.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.org.apache.xpath.internal.operations.Bool;

import ast.ASTNode;
import ast.functionDef.FunctionDef;
import ast.statements.Condition;
import parsing.ModuleParser;
import parsing.C.Modules.ANTLRCModuleParserDriver;
import tools.safepatch.SafepatchASTWalker;
import tools.safepatch.SafepatchMain;
import tools.safepatch.SafepatchPreprocessor;
import tools.safepatch.SafepatchPreprocessor.PREPROCESSING_METHOD;
import tools.safepatch.cfgclassic.BasicBlock;
import tools.safepatch.fgdiff.StatementMap;
import tools.safepatch.fgdiff.StatementMap.MAP_TYPE;
import tools.safepatch.flowres.FlowRestrictiveChecker;
import tools.safepatch.flowres.FlowRestrictiveChecker.SATISFIABLE_FLAG;
import tools.safepatch.flowres.FunctionMap;
import tools.safepatch.flowres.FunctionMatcher;
import tools.safepatch.flowres.FunctionMatcher.MATCHING_METHOD;
import tools.safepatch.flowres.InsertedStatementChecker;
import tools.safepatch.flowres.MovedStatementChecker;

public class FunctionDiffCheck {

	private static final Logger logger = LogManager.getLogger();
	private boolean removePreProcess = true;

	private ANTLRCModuleParserDriver driver = new ANTLRCModuleParserDriver();
	private ModuleParser parser = new ModuleParser(driver);
	private SafepatchASTWalker astWalker = new SafepatchASTWalker();

	public static void main (String[] args) {
		FunctionDiffCheck fdc = new FunctionDiffCheck();
		
		List<FunctionMap> funs = fdc.getDiffFunctions("/home/utente/ucsb-workspace/kerneline/results/CVE-2011-4914/e0bccd315db0c2f919e7fcf9cb60db21d9986f52/rose_subr.c", "/home/utente/ucsb/project-stuff/linux/net/rose/rose_subr.c");
		
		for(FunctionMap f: funs) {
			System.out.println(f.getOldFunction().name.getCompleteCodeContent());
		}
	}
	
	public List<FunctionMap> getDiffFunctions(String srcFileName, String dstFileName) {
		org.apache.logging.log4j.core.config.Configurator.setRootLevel(Level.DEBUG);

		File srcFile = new File(srcFileName);
		File dstFile = new File(dstFileName);
		File srcPreprocessFile = new File(srcFileName + ".preprocess");
		File dstPreprocessFile = new File(dstFileName + ".preprocess");
		
		try {

			// pre-process the files.
			if (this.preprocessFile(srcFile, srcPreprocessFile)) {
				logger.info("Preprocessed the src file:{} to {}", srcFile.getAbsolutePath(),
						srcPreprocessFile.getAbsolutePath());
			}
			if (this.preprocessFile(dstFile, dstPreprocessFile)) {
				logger.info("Preprocessed the dst file:{} to {}", srcFile.getAbsolutePath(),
						srcPreprocessFile.getAbsolutePath());
			}

			String srcPreProPath = srcPreprocessFile.getAbsolutePath();
			String dstPreProPath = dstPreprocessFile.getAbsolutePath();
			parser.addObserver(astWalker);
			parser.parseFile(srcPreProPath);
			parser.parseFile(dstPreProPath);

			// After parsing a file the SafepatchASTWalker saves a list of the function AST
			// nodes in a Map,
			// for every parsed file.
			ArrayList<FunctionDef> oldFunctionList = astWalker.getFileFunctionList().get(srcPreProPath);
			ArrayList<FunctionDef> newFunctionList = astWalker.getFileFunctionList().get(dstPreProPath);
			String diffAnalyzableReason = isDiffAnalyzable(oldFunctionList, newFunctionList);

			// sanity check
			if (diffAnalyzableReason != null) {
				logger.error("Give files are not analyzable by the current system.");
				// printWriter.write("\"nonanalyzable\": \"" + diffAnalyzableReason + "\"");

			}
			
			// ok the files are analyzable.
			// go-on and do the stuff.
			FunctionMatcher currMatcher = new FunctionMatcher(oldFunctionList, newFunctionList,
					MATCHING_METHOD.NAME_ONLY);
			currMatcher.match();

			List<FunctionMap> allFunctionMap = currMatcher.getCommonFunctions();

			// now process the functions that changed.
			for (FunctionMap currMap : allFunctionMap) {
				if (!currMap.processFunctions()) {
					logger.error("Error occured while processing function diff");
				}
			}

			// OK, now get only those functions that differ.
			List<FunctionMap> diffFunctions = new ArrayList<FunctionMap>();
			for (FunctionMap fmap : allFunctionMap) {
				if (!fmap.areSame()) {
					diffFunctions.add(fmap);
				}
			}

			return diffFunctions;

		} catch (Exception e) {
			e.printStackTrace();
			logger.error("Error occured in getDiffFunctions function: {}", e.getMessage());
			return null;
		} finally {
			// clean up
			if (this.removePreProcess) {
				if (srcPreprocessFile.isFile()) {
					srcPreprocessFile.delete();
				}
				if (dstPreprocessFile.isFile()) {
					dstPreprocessFile.delete();
				}
			}
		}

	}

	private boolean isPatchSafe(FunctionMap targetMap, PrintWriter jsonWriter) {
		boolean retVal = true;
		jsonWriter.write("\"funcName\": \"" + targetMap.getOldFunction().getLabel() + "\",");
		targetMap.computeMappedConditions();
		FlowRestrictiveChecker currChecker = new FlowRestrictiveChecker(targetMap);
		currChecker.computeConditionsToCheck();
		// check implication.
		currChecker.checkMatchedConditionsImplication();
		// check the validity of the implication result.

		HashMap<ASTNode, SATISFIABLE_FLAG> conCheckFlags = currChecker.getConCheckFlags();
		HashMap<ASTNode, ASTNode> checkedConds = currChecker.getConditionsToCheck();
		jsonWriter.write("\"numCond\":" + Integer.toString(checkedConds.keySet().size()) + ",");
		for (ASTNode oldCond : checkedConds.keySet()) {
			SATISFIABLE_FLAG satisFlag = conCheckFlags.get(oldCond);
			BasicBlock oldBB = targetMap.getOldClassicCFG().getBB(oldCond);
			BasicBlock newBB = targetMap.getNewClassicCFG().getBB(checkedConds.get(oldCond));
			if (satisFlag != SATISFIABLE_FLAG.SAME) {
				boolean newImpOld = true;
				if (newBB.isNegativeErrorGuarding()) {
					// error handling
					newImpOld = false;
				}

				if (newImpOld) {
					if (satisFlag == SATISFIABLE_FLAG.NEW_IMPL_OLD) {
						logger.debug("New condition: {} imply old condition: {}",
								checkedConds.get(oldCond).getEscapedCodeStr(), oldCond.getEscapedCodeStr());
					} else {
						logger.debug("New condition: {} does not imply old condition: {}",
								checkedConds.get(oldCond).getEscapedCodeStr(), oldCond.getEscapedCodeStr());
						retVal = false;
					}
				} else {
					if (satisFlag == SATISFIABLE_FLAG.OLD_IMPL_NEW) {
						logger.debug("Old condition: {} imply new condition: {}",
								checkedConds.get(oldCond).getEscapedCodeStr(), oldCond.getEscapedCodeStr());
					} else {
						logger.debug("Old condition: {} does not imply new condition: {}", oldCond.getEscapedCodeStr(),
								checkedConds.get(oldCond).getEscapedCodeStr());
						retVal = false;
					}
				}
			} else {
				logger.debug("New condition: {} is same as old condition: {}",
						checkedConds.get(oldCond).getEscapedCodeStr(), oldCond.getEscapedCodeStr());
			}
		}

		jsonWriter.write("\"condResult\":" + Boolean.toString(retVal) + ",");

		if (this.checkUpdatedStmts(targetMap, currChecker, jsonWriter)) {
			logger.debug("All updated statements are safe");
		} else {
			logger.debug("Unable to handle one or more updated statements");
			retVal = false;
		}

		// check inserted statements.
		InsertedStatementChecker insertChecker = new InsertedStatementChecker(targetMap, currChecker);
		if (insertChecker.areInsertedStatementsSafe(jsonWriter)) {
			logger.debug("All inserted statements are safe");
		} else {
			logger.debug("Unable to handle one or more inserted statements");
			retVal = false;
		}

		// check moved statements.
		MovedStatementChecker movedChecker = new MovedStatementChecker(targetMap);
		if (movedChecker.areMovedStatementsSafe(jsonWriter)) {
			logger.debug("All moved statements are safe");
		} else {
			logger.debug("Unable to handle one or more moved statements.");
			retVal = false;
		}

		if (this.onlyDeletePatch(targetMap)) {
			logger.debug("This is a delete only patch, we cannot handle this");
			retVal = false;
			jsonWriter.write("\"deleteOnlyPatch\": \"true\",");
		} else {
			jsonWriter.write("\"deleteOnlyPatch\": \"false\" ,");
		}

		/*
		 * if(FlowRestrictiveMain.hasDeletedConditions(targetMap)) {
		 * logger.debug("Has deleted conditions"); retVal = false; }
		 */
		jsonWriter.write("\"safepatch\":" + Boolean.toString(retVal));
		return retVal;
	}

	private boolean onlyDeletePatch(FunctionMap targetMap) {
		boolean retVal = true;
		for (StatementMap currMap : targetMap.getStatementMap()) {
			if (!(currMap.getMapType() == MAP_TYPE.UNMODIFIED || currMap.getMapType() == MAP_TYPE.UNDEFINED
					|| currMap.getMapType() == MAP_TYPE.DELETE)) {
				retVal = false;
				break;
			}
		}
		return retVal;
	}

	private boolean hasDeletedConditions(FunctionMap targetMap) {
		for (StatementMap currMap : targetMap.getStatementMap()) {
			if (currMap.getMapType() == MAP_TYPE.DELETE && currMap.getOriginal() instanceof Condition) {
				return true;
			}
		}
		return false;
	}

	private boolean checkUpdatedStmts(FunctionMap targetMap, FlowRestrictiveChecker targetChecker,
			PrintWriter jsonWriter) {
		boolean retVal = true;
		int numSt = 0;
		// check that all the updated statements are either handled by condition or are
		// in error BBs
		for (StatementMap currMap : targetMap.getStatementMap()) {
			if (currMap.getMapType() == MAP_TYPE.UPDATE && currMap.getOriginal() != null && currMap.getNew() != null) {
				numSt++;
				ASTNode oldSt = currMap.getOriginal();
				ASTNode newSt = currMap.getNew();
				// These statements are not handled by the flow res checker.
				if (!targetChecker.isOldStmtHandled(oldSt) && !targetChecker.isNewStmtHandled(newSt)) {
					// Check if these belong to error BBs
					BasicBlock oldBB = targetMap.getOldClassicCFG().getBB(oldSt);
					BasicBlock newBB = targetMap.getNewClassicCFG().getBB(newSt);
					if (!oldBB.isConfigErrorHandling() && !newBB.isConfigErrorHandling()) {
						retVal = false;
					} else {
						logger.debug("Statements old:{} or new{} belong to error handling code",
								oldSt.getEscapedCodeStr(), newSt.getEscapedCodeStr());
					}
				} else {
					logger.debug("Statement old: {} and new: {} are handled by flow res checked",
							oldSt.getEscapedCodeStr(), newSt.getEscapedCodeStr());
				}
			}
		}

		jsonWriter.write("\"numUpdated\":" + Integer.toString(numSt) + ",");
		jsonWriter.write("\"updatedResult\":" + Boolean.toString(retVal) + ",");
		return retVal;
	}

	private String isDiffAnalyzable(ArrayList<FunctionDef> oldFunctions, ArrayList<FunctionDef> newFunctions) {
		boolean retVal = true;
		if (SafepatchMain.containsDuplicates(oldFunctions) || SafepatchMain.containsDuplicates(newFunctions)) {
			return "CONDITIONAL COMPILATION";
		} else if (SafepatchMain.functionRenamed(oldFunctions, newFunctions)) {
			return "FUNCTIONS RENAMED";
		} else {
			retVal = oldFunctions.size() == newFunctions.size();
			if (!retVal) {
				return "FUNCTIONS ADDED OR REMOVED";
			}
		}
		return null;
	}

	private boolean preprocessFile(File srcFile, File dstFile) {
		boolean retVal = true;
		// TODO: finish this.
		try {
			SafepatchPreprocessor prep = new SafepatchPreprocessor(PREPROCESSING_METHOD.UNIFDEFALL);
			prep.preProcess(srcFile.getAbsolutePath(), dstFile.getAbsolutePath());
		} catch (Exception e) {
			logger.error(e.getMessage());
			retVal = false;
		}
		return retVal;
	}

}
