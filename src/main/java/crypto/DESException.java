package crypto;

public class DESException extends Exception
{
	public DESException()
	{
	}

	public DESException( String message )
	{
		super(message);
	}

	public DESException( String message, Throwable cause )
	{
		super(message, cause);
	}

	public DESException( Throwable cause )
	{
		super(cause);
	}

	public DESException( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace )
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
