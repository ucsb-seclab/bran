package ucsb.seclab.kerneline.utils;

public class FunctionNotFoundException extends Exception {
	
	private static final long serialVersionUID = 7768115321242254528L;
	
	private String message;
	
	public  FunctionNotFoundException(String message) {
		this.message = message;
	}
	
	public String getMessage() {
		return this.message;
	}

}
