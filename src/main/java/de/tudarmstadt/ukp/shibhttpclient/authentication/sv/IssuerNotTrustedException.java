package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

public class IssuerNotTrustedException extends Exception
{
    private static final long serialVersionUID = 2740383283959915460L;
    
    /**
     * 
     */
    public IssuerNotTrustedException()
    {
        super();
    }
    
    /**
     * @param message
     * @param cause
     */
    public IssuerNotTrustedException( String message, Throwable cause )
    {
        super( message, cause );
    }
    
    /**
     * @param message
     */
    public IssuerNotTrustedException( String message )
    {
        super( message );
    }
    
    /**
     * @param cause
     */
    public IssuerNotTrustedException( Throwable cause )
    {
        super( cause );
    }
}
