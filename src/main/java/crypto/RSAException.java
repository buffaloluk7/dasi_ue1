package crypto;

public class RSAException extends Exception {
	public RSAException() {
	}

	public RSAException(String message) {
		super(message);
	}

	public RSAException(String message, Throwable cause) {
		super(message, cause);
	}

	public RSAException(Throwable cause) {
		super(cause);
	}

	public RSAException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
