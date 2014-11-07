package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import de.tudarmstadt.ukp.shibhttpclient.authentication.SenderVouchesAuthenticator;

/**
 * A {@link SenderVouchesAuthenticator} that uses a callback to determine the userid that should be used for authentication.
 * 
 * @author fichtelmannm
 *
 */
public class CallbackSVAuthenticator extends SenderVouchesAuthenticator
{
    /**
     * A callback that determines the current user.
     * 
     * @author fichtelmannm
     *
     */
    public interface UserIdCallback
    {
        /**
         * Return the current user id.
         * 
         * @return the current user id.
         */
        String currentUser();
    }
    
    private UserIdCallback userIdCallback;
    
    /**
     * Creates a new {@link CallbackSVAuthenticator} with the specified callback.
     * 
     * @param userIdCallback
     *            the callback to determine the current user
     * @param signer
     *            the signer to create signed SV-tokens
     */
    public CallbackSVAuthenticator( UserIdCallback userIdCallback, TokenSigner signer )
    {
        super( null, signer );
        this.userIdCallback = userIdCallback;
    }
    
    @Override
    protected String currentUser()
    {
        return userIdCallback.currentUser();
    }
}
