package crypto;

public class AESException extends Exception
{
	public AESException()
	{
	}

	public AESException( String message )
	{
		super(message);
	}

	public AESException( String message, Throwable cause )
	{
		super(message, cause);
	}

	public AESException( Throwable cause )
	{
		super(cause);
	}

	public AESException( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace )
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
