package de.tudarmstadt.ukp.shibhttpclient.authentication;

public class CredentialException extends Exception
{
    private static final long serialVersionUID = 4608445528621002197L;
    
    /**
     * 
     */
    public CredentialException()
    {
        super();
    }
    
    /**
     * @param message
     * @param cause
     */
    public CredentialException( String message, Throwable cause )
    {
        super( message, cause );
    }
    
    /**
     * @param message
     */
    public CredentialException( String message )
    {
        super( message );
    }
    
    /**
     * @param cause
     */
    public CredentialException( Throwable cause )
    {
        super( cause );
    }
}
