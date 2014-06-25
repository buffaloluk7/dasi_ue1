package crypto;

public class KeyStorageException extends Exception {
	public KeyStorageException() {
	}

	public KeyStorageException(String message) {
		super(message);
	}

	public KeyStorageException(String message, Throwable cause) {
		super(message, cause);
	}

	public KeyStorageException(Throwable cause) {
		super(cause);
	}

	public KeyStorageException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
