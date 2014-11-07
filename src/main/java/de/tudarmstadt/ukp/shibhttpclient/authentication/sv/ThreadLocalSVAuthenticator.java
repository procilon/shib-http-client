package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import de.tudarmstadt.ukp.shibhttpclient.authentication.SenderVouchesAuthenticator;

/**
 * A {@link SenderVouchesAuthenticator} that stores the current user in a {@link ThreadLocal}.
 * 
 * @author fichtelmannm
 *
 */
public class ThreadLocalSVAuthenticator extends SenderVouchesAuthenticator
{
    private static final ThreadLocal<String> currentUser = new ThreadLocal<String>();
    
    /**
     * @param signer
     *            the signer to create signed SV-tokens
     */
    public ThreadLocalSVAuthenticator( TokenSigner signer )
    {
        super( null, signer );
    }
    
    /**
     * Assign the current user for this thread.
     * 
     * @param userId
     *            the user id
     */
    public void assignCurrentUser( String userId )
    {
        currentUser.set( userId );
    }
    
    /**
     * Detach the current user from this thread.
     */
    public void detachCurrentUser()
    {
        currentUser.remove();
    }
    
    @Override
    protected String currentUser()
    {
        String userId = currentUser.get();
        if ( userId != null )
        {
            return userId;
        }
        else
        {
            throw new IllegalStateException( "no userId assigned to the current thread" );
        }
    }
}
