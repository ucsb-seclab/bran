package ucsb.seclab.kerneline.model;

import java.util.*;

public class CVEHistory {
	
	private String cveId;
	
	private List<Revision> nonFixingChanges;
	
	private Revision fixingRevision;
	
	private Revision breakingRevision;
	
	public CVEHistory() {
		this.nonFixingChanges = new ArrayList<Revision>();
	}

	public Revision getBreakingRevision() {
		return breakingRevision;
	}

	public void setBreakingRevision(Revision breakingRevision) {
		this.breakingRevision = breakingRevision;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}


	public List<Revision> getNonFixingChanges() {
		return nonFixingChanges;
	}

	public void setNonFixingChanges(List<Revision> nonFixingChanges) {
		this.nonFixingChanges = nonFixingChanges;
	}

	public Revision getFixingRevision() {
		return fixingRevision;
	}

	public void setFixingRevision(Revision fixingRevision) {
		this.fixingRevision = fixingRevision;
	}
	
	public Revision getNonFixingChange(String commit) {
		for(Revision rev: this.nonFixingChanges) {
			if(rev.getCommit().equals(commit)) {
				return rev;
			}
		}
		
		return null;
	}
	
	public void setNonFixingChange(Revision toSet) {
		
		Iterator<Revision> iter = this.nonFixingChanges.iterator();
		
		while(iter.hasNext()) {
			if(iter.next().getCommit().equals(toSet.getCommit())) {
				iter.remove();
			}
		}
		
		this.nonFixingChanges.add(toSet);
	}
	
	public void setBreakingRevisionFunctions(List<Function> affectedFunctions) {
		this.breakingRevision.setAffectedFunctions(affectedFunctions);
	}
	
	public void setFixingRevisionFunctions(List<Function> affectedFunctions) {
		this.fixingRevision.setAffectedFunctions(affectedFunctions);
	}
	
	public boolean wasFunctionAffectedByBreakingRevision(String functionId) {
		for(Function f: this.breakingRevision.getAffectedFunctions()) {
			if(f.getId().equals(functionId)) {
				return true;
			}
		}
		
		return false;
	}
	
}
