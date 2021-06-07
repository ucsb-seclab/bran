package ucsb.seclab.kerneline.joern;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Session;
import org.neo4j.driver.v1.StatementResult;
import org.neo4j.driver.v1.Transaction;
import org.neo4j.driver.v1.TransactionWork;
import org.neo4j.driver.v1.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

import ucsb.seclab.kerneline.model.Function;
import ucsb.seclab.kerneline.utils.FunctionNotFoundException;
import ucsb.seclab.kerneline.utils.Utils;

public class JoernNeo4JDriver implements AutoCloseable {

	private Driver driver;

	private String filesFolder;

	private static JoernNeo4JDriver single_instance = null;

	private static final Logger logger = LoggerFactory.getLogger(JoernNeo4JDriver.class);

	public void init(String uri, String user, String password) {
		this.driver = GraphDatabase.driver(uri);
	}

	private JoernNeo4JDriver() {

	}

	public static JoernNeo4JDriver getInstance() {
		if (single_instance == null)
			single_instance = new JoernNeo4JDriver();

		return single_instance;
	}

	public List<Record> sendQuery(String query) {
		try (Session session = driver.session()) {
			List<Record> res = session.writeTransaction(new TransactionWork<List<Record>>() {

				@Override
				public List<Record> execute(Transaction tx) {

					StatementResult result = tx.run(query);

					return result.list();
				}
			});

			return res;
		}
	}

	public Map<String, Object> getAst(String funName, String filepath) {
		List<Record> res = this.sendQuery("MATCH p=(file:File{filepath: '" + filepath
				+ "'})-[:IS_FILE_OF]->(fun:Function{name:'" + funName
				+ "'})-[:IS_FUNCTION_OF_AST]->(ast)-[:IS_AST_PARENT*]->(m) WITH COLLECT(p) AS ps CALL apoc.convert.toTree(ps) yield value RETURN value;");
		if (res != null && !res.isEmpty()) {
			return res.get(0).asMap();
		} else {
			return null;
		}
	}

	public Value getCFGInit(Function f, String outputDir) {

		String tmpFilePath = f.getFile();
		tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];
		try (Session session = driver.session()) {
			Record init = session.writeTransaction(new TransactionWork<Record>() {
				@Override
				public Record execute(Transaction tx) {

					String tmpFilePath = f.getFile();
					if (f.getIsVulnerable()) {
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];
						StatementResult result = tx.run("MATCH (file:File{filepath: '" + outputDir + "/"
								+ f.getFixingCve() + "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(fun:Function{name: '" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_CFG]->(cfg)-[:FLOWS_TO]->(init) RETURN init;");
						return result.list().get(0);

					} else {
						StatementResult result = tx.run("MATCH (file:File{filepath: '" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(fun:Function{name: '" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_CFG]->(cfg)-[:FLOWS_TO]->(init) RETURN init;");
						return result.list().get(0);

					}
				}
			});

			return init.get("init");
		} catch (IndexOutOfBoundsException e) {
			return null;
		}
	}

	public List<Value> getAllIdsInConditions(Function f, String outputDir) {
		List<Value> toReturn = new ArrayList<Value>();
		try (Session session = driver.session()) {
			List<Record> idsInConditions = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					if (f.getIsVulnerable()) {

						String tmpFilePath = f.getFile();
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult result = tx.run("MATCH (file:File {filepath : '" + outputDir + "/"
								+ f.getFixingCve() + "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(fun:Function{name:'" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_AST]->(ast)-[:IS_AST_PARENT*]->(if{type: 'IfStatement'})-[:IS_AST_PARENT*]->(cond{type: 'Condition'})-[:IS_AST_PARENT*]->(id{type: 'Identifier'}) RETURN id;");
						return result.list();
					} else {
						StatementResult result = tx.run("MATCH (file:File {filepath : '" + f.getFile()
								+ "'})-[:IS_FILE_OF]->(fun:Function{name:'" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_AST]->(ast)-[:IS_AST_PARENT*]->(if{type: 'IfStatement'})-[:IS_AST_PARENT*]->(cond{type: 'Condition'})-[:IS_AST_PARENT*]->(id{type: 'Identifier'}) RETURN id;");
						return result.list();
					}
				}
			});

			for (Record r : idsInConditions) {
				toReturn.add(r.get("id"));
			}

			return toReturn;
		}
	}

	public List<String> getAllFunctionsFromCodebase(Integer limit, List<String> subfolders)
			throws FunctionNotFoundException {

		List<String> functionNames = new ArrayList<String>();

		try (Session session = driver.session()) {
			List<Record> functions = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					if (limit > 0) {
						if (subfolders.size() == 0) {
							StatementResult result = tx
									.run("MATCH (f:Function) RETURN f.name AS name LIMIT " + limit + ";");
							return result.list();
						} else {
							int funPerSub = limit / subfolders.size();
							List<Record> toReturn = new ArrayList<Record>();
							for (String sub : subfolders) {
								StatementResult result = tx.run(
										"MATCH (file:File)-[:IS_FILE_OF]->(functions:Function) WHERE file.filepath contains '/"
												+ sub + "/' RETURN functions.name AS name LIMIT " + funPerSub + ";");
								toReturn.addAll(result.list());
							}
							return toReturn;
						}
					} else {
						if (subfolders.size() == 0) {
							StatementResult result = tx.run("MATCH (f:Function) RETURN f.name AS name;");
							return result.list();
						} else {
							List<Record> toReturn = new ArrayList<Record>();
							for (String sub : subfolders) {
								StatementResult result = tx.run(
										"MATCH (file:File)-[:IS_FILE_OF]->(functions:Function) WHERE file.filepath contains '/"
												+ sub + "/' RETURN functions.name AS name;");
								toReturn.addAll(result.list());
							}
							return toReturn;
						}

					}
				}
			});

			logger.info("Number of record returned by Neo4J: " + functions.size());
			for (Record r : functions) {
				functionNames.add(r.get("name").toString().replaceAll("\"", ""));
			}
		}

		return functionNames;
	}

	public List<Value> getNumCastExpressions(Function f, String outputDir) {
		List<Value> toReturn = new ArrayList<Value>();

		try (Session session = driver.session()) {
			List<Record> casts = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					String tmpFilePath = f.getFile();
					if (f.getIsVulnerable()) {
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult result = tx.run("MATCH (file:File{filepath: '" + outputDir + "/"
								+ f.getFixingCve() + "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]-> (n:Function {name:'" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_AST]->(ast)-[:IS_AST_PARENT*]->(cast {type:'CastExpression'}) RETURN cast;");
						return result.list();
					} else {
						StatementResult result = tx.run("MATCH (file:File {filepath: '" + tmpFilePath
								+ "'})-[:IS_FILE_OF]-> (n:Function {name:'" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_AST]->(ast)-[:IS_AST_PARENT*]->(cast {type:'CastExpression'}) RETURN cast;");
						return result.list();
					}
				}
			});

			for (Record r : casts) {
				toReturn.add(r.get("cast"));
			}
		}

		return toReturn;
	}

	public List<Value> getCoLocatedFunctions(Function f, String outputDir) {
		List<Value> toReturn = new ArrayList<Value>();

		try (Session session = driver.session()) {
			// query joern database in neo4j to get the set of functions in the same file of
			// f

			List<Record> coLocatedFunctions = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					if (f.getIsVulnerable()) {

						String tmpFilePath = f.getFile();
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult result = tx.run("MATCH (file:File {filepath : '" + outputDir + "/"
								+ f.getFixingCve() + "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(functions) RETURN functions;");
						return result.list();
					} else {
						StatementResult result = tx.run("MATCH (file:File {filepath : '" + f.getFile()
								+ "'})-[:IS_FILE_OF]->(functions) RETURN functions;");
						return result.list();
					}
				}
			});

			for (Record r : coLocatedFunctions) {
				toReturn.add(r.get("functions"));
			}
		}

		return toReturn;
	}

	public List<Function> extractCoLocatedFunctions(Function f) {

		List<Function> toReturn = new ArrayList<Function>();
		Function tmp = null;

		try (Session session = driver.session()) {
			// query joern database in neo4j to get the set of functions in the same file of
			// f
			List<Record> coLocatedFunctions = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult result = tx.run("MATCH (file:File {filepath : '" + f.getFile()
							+ "'})-[:IS_FILE_OF]->(functions) RETURN functions;");
					return result.list();
				}
			});

			// initialize a Function for each returned record
			for (Record r : coLocatedFunctions) {
				tmp = new Function();
				tmp.setName(r.get("functions").get("name").toString().replaceAll("\"", ""));
				tmp.setFile(f.getFile());
				toReturn.add(tmp);
			}
		}

		List<Function> toDrop = new ArrayList<Function>();
		for (Function cl : toReturn) {

			String body = Utils.extractFunctionBodyFromFile(cl.getFile(), cl.getName());

			if (body == null) {
				logger.info("Dropping joern retrieved function due to empty extracted body: " + cl.getName() + " "
						+ cl.getFile());
				toDrop.add(cl);
			} else {
				cl.setBody(body);
			}
		}

		for (Function drop : toDrop) {
			toReturn.remove(drop);
		}

		return toReturn;
	}

	public List<Value> getInputParameters(Function f, String outputDir) {
		// MATCH (n {type:'Function',
		// name:'encode_float'})-[:IS_FUNCTION_OF_CFG]->(cfg)-[:FLOWS_TO*]->(param
		// {type:'Parameter'}) RETURN param;

		List<Value> toReturn = new ArrayList<Value>();

		try (Session session = driver.session()) {
			List<Record> params = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					if (f.getIsVulnerable()) {

						String tmpFilePath = f.getFile();
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult result = tx.run("MATCH (file:File {filepath : '" + outputDir + "/"
								+ f.getFixingCve() + "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath + "'})"
								+ "-[:IS_FILE_OF]->(fun:Function{name: '" + f.getName() + "'})"
								+ "-[:IS_FUNCTION_OF_AST]-(ast)"
								+ "-[:IS_AST_PARENT*]->(param{type:'Parameter'})"
								+ " RETURN param;");
						return result.list();
					} else {
						StatementResult result = tx.run("MATCH (file:File {filepath : '" + f.getFile() + "'})"
								+ "-[:IS_FILE_OF]->(fun:Function{name: '" + f.getName() + "'})"
								+ "-[:IS_FUNCTION_OF_AST]-(ast)"
								+ "-[:IS_AST_PARENT*]->(param{type:'Parameter'})"
								+ " RETURN param;");
						return result.list();
					}
				}
			});

			for (Record r : params) {
				toReturn.add(r.get("param"));
			}
		}

		return toReturn;
	}

	public Integer getNumNullPtrAccess(Function f, String outputDir) {

		try (Session session = driver.session()) {
			List<Record> kernProps = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					String tmpFilePath = f.getFile();
					if (f.getIsVulnerable()) {
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult r = tx.run("MATCH (file:File {filepath: '" + outputDir + "/" + f.getFixingCve()
								+ "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(f:Function{name: '" + f.getName()
								+ "'})-[:HAS_KERNALINE_PROPERTY]->(p) return p");
						return r.list();
					} else {
						StatementResult r = tx.run(
								"MATCH (file:File {filepath: '" + tmpFilePath + "'})-[:IS_FILE_OF]->(f:Function{name: '"
										+ f.getName() + "'})-[:HAS_KERNALINE_PROPERTY]->(p) return p");
						return r.list();
					}

				}
			});

			for (Record p : kernProps) {
				if (!p.get("p").get("NUM_NULL_PTR_ACCESS").toString().equals("NULL")) {
					return Integer.parseInt(p.get("p").get("NUM_NULL_PTR_ACCESS").toString());
				}
			}

			return null;

		}

	}

	public Integer getNumPtrModification(Function f, String outputDir) {

		try (Session session = driver.session()) {
			List<Record> kernProps = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					String tmpFilePath = f.getFile();
					if (f.getIsVulnerable()) {
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];
						StatementResult r = tx.run("MATCH (file:File{filepath: '" + outputDir + "/" + f.getFixingCve()
								+ "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->(f:Function{name: '" + f.getName()
								+ "'})-[:HAS_KERNALINE_PROPERTY]->(p) return p");
						return r.list();
					} else {
						StatementResult r = tx.run(
								"MATCH (file:File{filepath: '" + tmpFilePath + "'})-[:IS_FILE_OF]->(f:Function{name: '"
										+ f.getName() + "'})-[:HAS_KERNALINE_PROPERTY]->(p) return p");
						return r.list();
					}
				}
			});

			for (Record p : kernProps) {
				if (!p.get("p").get("NUM_PTR_MODIFICATION").toString().equals("NULL")) {
					return Integer.parseInt(p.get("p").get("NUM_PTR_MODIFICATION").toString());
				}
			}
			return null;
		}

	}

	public List<Value> getDeclaredVarsIds(Function f, String outputDir) {
		List<Value> toReturn = new ArrayList<Value>();

		try (Session session = driver.session()) {
			List<Record> declIds = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {

					if (f.getIsVulnerable()) {

						String tmpFilePath = f.getFile();
						tmpFilePath = tmpFilePath.split("/")[tmpFilePath.split("/").length - 1];

						StatementResult r = tx.run("MATCH (file:File{filepath: '" + outputDir + "/" + f.getFixingCve()
								+ "/" + f.getFixingCommit() + "/" + filesFolder + "/" + tmpFilePath
								+ "'})-[:IS_FILE_OF]->" + "(fun:Function{name: '" + f.getName()
								+ "'})-[:IS_FUNCTION_OF_AST]->" + "(ast)-[:IS_AST_PARENT*]->"
								+ "(idstm{type: 'IdentifierDeclStatement'})-[:IS_AST_PARENT*]->"
								+ "(id{type: 'Identifier'}) RETURN id;");
						return r.list();
					} else {
						StatementResult r = tx.run("MATCH (file:File{filepath: '" + f.getFile() + "'})-[:IS_FILE_OF]->"
								+ "(fun:Function{name: '" + f.getName() + "'})-[:IS_FUNCTION_OF_AST]->"
								+ "(ast)-[:IS_AST_PARENT*]->"
								+ "(idstm{type: 'IdentifierDeclStatement'})-[:IS_AST_PARENT*]->"
								+ "(id{type: 'Identifier'}) RETURN id;");
						return r.list();
					}
				}
			});

			for (Record r : declIds) {
				toReturn.add(r.get("id"));
			}

		}

		return toReturn;
	}

	public String getIsFileOf(String f) {
		try (Session session = driver.session()) {
			List<Record> file = session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx
							.run("MATCH (file:File)-[:IS_FILE_OF]->(fun:Function {name:'" + f + "'}) RETURN file;");
					return r.list();
				}
			});

			return file.get(0).get("file").get("filepath").toString().replaceAll("\"", "");
		}
	}

	public void initializeFileIndex() {
		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("match (n{type: 'File'}) set n :File return n;");
					return r.list();
				}
			});
		}

		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("CREATE INDEX ON :File(filepath);");
					return r.list();
				}
			});
		}
	}

	public void initializeFunctionIndex() {
		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("match (n{type: 'Function'}) set n :Function return n;");
					return r.list();
				}
			});
		}

		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("CREATE INDEX ON :Function(name);");
					return r.list();
				}
			});
		}
	}

	public void initializeCFGInitIndex() {
		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("match (n{type: 'CFGEntryNode'}) set n :CFGEntryNode return n;");
					return r.list();
				}
			});
		}

		try (Session session = driver.session()) {
			session.writeTransaction(new TransactionWork<List<Record>>() {
				@Override
				public List<Record> execute(Transaction tx) {
					StatementResult r = tx.run("CREATE INDEX ON :CFGEntryNode(functionId);");
					return r.list();
				}
			});
		}
	}

	@Override
	public void close() throws Exception {
		driver.close();
	}

	public String getFilesFolder() {
		return filesFolder;
	}

	public void setFilesFolder(String filesFolder) {
		this.filesFolder = filesFolder;
	}

}
