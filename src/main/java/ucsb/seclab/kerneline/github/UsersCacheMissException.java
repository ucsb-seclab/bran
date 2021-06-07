package ucsb.seclab.kerneline.github;

public class UsersCacheMissException extends Exception {
	
	private static final long serialVersionUID = -7693329145856515898L;
	
	private String message;
	
	public  UsersCacheMissException(String message) {
		this.message = message;
	}
	
	public String getMessage() {
		return this.message;
	}

}
