package ucsb.seclab.kerneline.model;

import java.util.List;

public class Revision {
	
	private  List<Function> affectedFunctions;
	
	private String commit;

	public List<Function> getAffectedFunctions() {
		return affectedFunctions;
	}

	public void setAffectedFunctions(List<Function> affectedFunctions) {
		this.affectedFunctions = affectedFunctions;
	}

	public String getCommit() {
		return commit;
	}

	public void setCommit(String commit) {
		this.commit = commit;
	}
	
}
