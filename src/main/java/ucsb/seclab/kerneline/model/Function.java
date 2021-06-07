package ucsb.seclab.kerneline.model;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class Function implements Serializable {

	private static final long serialVersionUID = -8683247539255088832L;

	private String sha;
	
	private String id;
	
	private String body;
	
	private Map<String, Object> ast;

	public Map<String, Object> getAst() {
		return ast;
	}

	public void setAst(Map<String, Object> ast) {
		this.ast = ast;
	}
	
	private Boolean isVulnerable;
	
	private String name;
	
	private String file;
	
	private String fileRelative;

	private Integer loc; 
	
	private Integer moduleLoc;
	
	private Double complexity;
	
	private Double moduleComplexity;
	
	private Double coChangingModuleComplexity;
	
	private Integer coChangingModuleLoc;
	
	private Integer nChanges;
	
	private Integer moduleNChanges;
	
	private Integer nAuthors;
	
	private Integer moduleNAuthors;
	
	private Integer numberOfInputParameters;
	
	private Integer numberOfDeclaredVars;
	
	private Integer numberOfCoLocatedFunctions;
	
	private Integer numberOfSanityChecksOnParameters;
	
	private Integer numberOfCastExpressions;
	
	private Double avgContributorsFollowers;
	
	private Double avgContributorsSubscribers;
	
	private Double avgContributorsWatchers;
	
	private Double avgContributorsStars;

	private Double avgContributorsPublicRepos;
	
	private Double avgContributorsForks;

	public Double getAvgContributorsFollowers() {
		return avgContributorsFollowers;
	}

	public void setAvgContributorsFollowers(Double avgContributorsFollowers) {
		this.avgContributorsFollowers = avgContributorsFollowers;
	}

	public Double getAvgContributorsSubscribers() {
		return avgContributorsSubscribers;
	}

	public void setAvgContributorsSubscribers(Double avgContributorsSubscribers) {
		this.avgContributorsSubscribers = avgContributorsSubscribers;
	}

	public Double getAvgContributorsWatchers() {
		return avgContributorsWatchers;
	}

	public void setAvgContributorsWatchers(Double avgContributorsWatchers) {
		this.avgContributorsWatchers = avgContributorsWatchers;
	}

	public Double getAvgContributorsStars() {
		return avgContributorsStars;
	}

	public void setAvgContributorsStars(Double avgContributorsStars) {
		this.avgContributorsStars = avgContributorsStars;
	}

	public Double getAvgContributorsPublicRepos() {
		return avgContributorsPublicRepos;
	}

	public void setAvgContributorsPublicRepos(Double avgContributorsPublicRepos) {
		this.avgContributorsPublicRepos = avgContributorsPublicRepos;
	}

	public Double getAvgContributorsForks() {
		return avgContributorsForks;
	}

	public void setAvgContributorsForks(Double avgContributorsForks) {
		this.avgContributorsForks = avgContributorsForks;
	}

	public Integer getNumberOfNullPtrAccess() {
		return numberOfNullPtrAccess;
	}

	public void setNumberOfNullPtrAccess(Integer numberOfNullPtrAccess) {
		this.numberOfNullPtrAccess = numberOfNullPtrAccess;
	}

	private Integer numberOfNullPtrAccess;

	private Integer numberOfPtrModification;

	public Integer getNumberOfPtrModification() {
		return numberOfPtrModification;
	}

	public void setNumberOfPtrModification(Integer numberOfPtrModification) {
		this.numberOfPtrModification = numberOfPtrModification;
	}

	public Integer getNumberOfSanityChecksOnParameters() {
		return numberOfSanityChecksOnParameters;
	}

	public void setNumberOfSanityChecksOnParameters(Integer numberOfSanityChecksOnParameters) {
		this.numberOfSanityChecksOnParameters = numberOfSanityChecksOnParameters;
	}

	public Integer getNumberOfLinesOfComment() {
		return numberOfLinesOfComment;
	}

	public void setNumberOfLinesOfComment(Integer numberOfLinesOfComment) {
		this.numberOfLinesOfComment = numberOfLinesOfComment;
	}

	private Integer numberOfLinesOfComment;
	
	public Integer getNumberOfCoLocatedFunctions() {
		return numberOfCoLocatedFunctions;
	}

	public void setNumberOfCoLocatedFunctions(Integer numberOfCoLocatedFunctions) {
		this.numberOfCoLocatedFunctions = numberOfCoLocatedFunctions;
	}

	public Integer getNumberOfDeclaredVars() {
		return numberOfDeclaredVars;
	}

	public void setNumberOfDeclaredVars(Integer numberOfDeclaredVars) {
		this.numberOfDeclaredVars = numberOfDeclaredVars;
	}

	public Integer getNumberOfInputParameters() {
		return numberOfInputParameters;
	}

	public void setNumberOfInputParameters(Integer numberOfInputParameters) {
		this.numberOfInputParameters = numberOfInputParameters;
	}

	// only set if isVulnerable = true
	private String fixingCommit;
	
	// only set if isVulnerable = true
	private String fixingCve;

	public String getFixingCve() {
		return fixingCve;
	}

	public void setFixingCve(String fixingCve) {
		this.fixingCve = fixingCve;
	}

	public Integer getnChanges() {
		return nChanges;
	}

	public void setnChanges(Integer nChanges) {
		this.nChanges = nChanges;
	}

	public Integer getModuleNChanges() {
		return moduleNChanges;
	}

	public void setModuleNChanges(Integer moduleNChanges) {
		this.moduleNChanges = moduleNChanges;
	}

	public Integer getnAuthors() {
		return nAuthors;
	}

	public void setnAuthors(Integer nAuthors) {
		this.nAuthors = nAuthors;
	}

	public Integer getModuleNAuthors() {
		return moduleNAuthors;
	}

	public void setModuleNAuthors(Integer moduleNAuthors) {
		this.moduleNAuthors = moduleNAuthors;
	}

	private List<Double> tfidf;
	
	private List<Long> tf;

	private List<Double> doc2vec;
	
	private List<Double> avgWord2vec;
	
	private List<Double> avgWord2vecTfidf;
	
	private Integer charCount;
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getFile() {
		return file;
	}

	public void setFile(String file) {
		this.file = file;
	}

	public String getFixingCommit() {
		return fixingCommit;
	}

	public void setFixingCommit(String fixingCommit) {
		this.fixingCommit = fixingCommit;
	}
	
	public Boolean getIsVulnerable() {
		return isVulnerable;
	}

	public void setIsVulnerable(Boolean isVulnerable) {
		this.isVulnerable = isVulnerable;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}

	public Integer getLoc() {
		return loc;
	}

	public void setLoc(Integer loc) {
		this.loc = loc;
	}

	public Double getComplexity() {
		return complexity;
	}

	public Integer getModuleLoc() {
		return moduleLoc;
	}

	public void setModuleLoc(Integer moduleLoc) {
		this.moduleLoc = moduleLoc;
	}

	public Double getModuleComplexity() {
		return moduleComplexity;
	}

	public void setModuleComplexity(Double moduleComplexity) {
		this.moduleComplexity = moduleComplexity;
	}

	public Double getCoChangingModuleComplexity() {
		return coChangingModuleComplexity;
	}

	public void setCoChangingModuleComplexity(Double coChangingModuleComplexity) {
		this.coChangingModuleComplexity = coChangingModuleComplexity;
	}

	public Integer getCoChangingModuleLoc() {
		return coChangingModuleLoc;
	}

	public void setCoChangingModuleLoc(Integer coChangingModuleLoc) {
		this.coChangingModuleLoc = coChangingModuleLoc;
	}

	public void setComplexity(Double cycComplexity) {
		this.complexity = cycComplexity;
	}

	public List<Double> getDoc2vec() {
		return doc2vec;
	}

	public void setDoc2vec(List<Double> doc2vec) {
		this.doc2vec = doc2vec;
	}

	public List<Double> getAvgWord2vec() {
		return avgWord2vec;
	}

	public void setAvgWord2vec(List<Double> avgWord2vec) {
		this.avgWord2vec = avgWord2vec;
	}

	public List<Double> getAvgWord2vecTfidf() {
		return avgWord2vecTfidf;
	}

	public void setAvgWord2vecTfidf(List<Double> avgWord2vecTfidf) {
		this.avgWord2vecTfidf = avgWord2vecTfidf;
	}

	public Integer getCharCount() {
		return charCount;
	}

	public void setCharCount(Integer charCount) {
		this.charCount = charCount;
	}
		
	@Override
	public String toString() {

		StringBuilder sb = new StringBuilder();

		sb.append(this.id).append(",");
		sb.append(this.loc).append(",");
		sb.append(this.complexity).append(",");;
		sb.append(this.moduleLoc).append(",");
		sb.append(this.moduleComplexity).append(",");
		
		sb.append(this.nChanges).append(",");
		sb.append(this.moduleNChanges).append(",");;
		sb.append(this.nAuthors).append(",");
		sb.append(this.moduleNAuthors).append(",");
		
		//sb.append(this.coChangingModuleLoc).append(",");
		//sb.append(this.coChangingModuleComplexity).append(",");
		
		sb.append(this.numberOfInputParameters).append(",");
		sb.append(this.numberOfDeclaredVars).append(",");
		sb.append(this.numberOfCoLocatedFunctions).append(",");
		sb.append(this.numberOfLinesOfComment).append(",");
		sb.append(this.numberOfSanityChecksOnParameters).append(",");
		sb.append(this.numberOfCastExpressions).append(",");
		sb.append(this.numberOfNullPtrAccess).append(",");
		sb.append(this.numberOfPtrModification).append(",");

		sb.append(this.avgContributorsFollowers).append(",");
		sb.append(this.avgContributorsForks).append(",");
		sb.append(this.avgContributorsPublicRepos).append(",");
		sb.append(this.avgContributorsStars).append(",");
		sb.append(this.avgContributorsWatchers).append(",");

/*		
		for(Double v: this.doc2vec) {
			sb.append(v).append(",");
		}
		
		for(Long v: this.tf) {
			sb.append(v).append(",");
		}
		
		for(Double v: this.tfidf) {
			sb.append(v).append(",");
		}
		
		for(Double v: this.avgWord2vec) {
			sb.append(v).append(",");
		}

		for(Double v: this.avgWord2vecTfidf) {
			sb.append(v).append(",");
		}
		*/
		
		sb.append(this.isVulnerable);

		
		

		return sb.toString();
	}

	public Integer getNumberOfCastExpressions() {
		return numberOfCastExpressions;
	}

	public void setNumberOfCastExpressions(Integer numberOfCastExpressions) {
		this.numberOfCastExpressions = numberOfCastExpressions;
	}

	public List<Double> getTfidf() {
		return tfidf;
	}

	public void setTfidf(List<Double> tfidf) {
		this.tfidf = tfidf;
	}

	public List<Long> getTf() {
		return tf;
	}

	public void setTf(List<Long> tf) {
		this.tf = tf;
	}
	
	public String getSha() {
		return sha;
	}

	public void setSha(String sha) {
		this.sha = sha;
	}
	
	
	public String getFileRelative() {
		return fileRelative;
	}

	public void setFileRelative(String fileRelative) {
		this.fileRelative = fileRelative;
	}
	
    @Override
    public int hashCode() {
        return (this.fixingCommit + this.name).hashCode();
    }
}
