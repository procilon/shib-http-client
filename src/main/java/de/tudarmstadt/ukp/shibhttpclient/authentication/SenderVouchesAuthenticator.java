package de.tudarmstadt.ukp.shibhttpclient.authentication;

import java.security.SignatureException;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpRequest;
import org.apache.http.client.HttpClient;
import org.bouncycastle.asn1.DERObject;

import de.tudarmstadt.ukp.shibhttpclient.authentication.sv.TokenSigner;
import de.tudarmstadt.ukp.shibhttpclient.authentication.sv.SignedToken;

/**
 * A {@link Authenticator} for Sender-vouches tokens.
 * 
 * <p>
 * Subclasses are encouraged to overwrite {@link #currentUser()} to determine the current user since a {@link HttpClient} is often reused.
 * </p>
 * 
 * @author fichtelmannm
 *
 */
public class SenderVouchesAuthenticator implements Authenticator
{
    private static final long ONE_MINUTE = 60000L;
    private String            userId;
    private TokenSigner          signer;
    
    /**
     * Creates a new {@link SenderVouchesAuthenticator} for a static user id.
     * 
     * @param userId
     *            the user id
     * @param signer
     *            the signer to create signed SV-tokens
     */
    public SenderVouchesAuthenticator( String userId, TokenSigner signer )
    {
        this.signer = signer;
        this.userId = userId;
    }
    
    @Override
    public void supplyCredentials( HttpRequest request ) throws CredentialException
    {
        Date now = new Date();
        Date in5Minutes = new Date( now.getTime() + ONE_MINUTE );
        SignedToken svToken = createdSignedToken( now, in5Minutes );
        DERObject token = svToken.getDERObject();
        
        String senderVouchesHeader = "Sender-Voucher " + DatatypeConverter.printBase64Binary( token.getDEREncoded() );
        
        request.addHeader( AUTH_HEADER, senderVouchesHeader );
    }
    
    /**
     * Return the current user id.
     * 
     * @return the current user id.
     */
    protected String currentUser()
    {
        return userId;
    }
    
    private SignedToken createdSignedToken( Date validFrom, Date validUntil ) throws CredentialException
    {
        try
        {
            return signer.createSignedToken( userId, validFrom, validUntil );
        }
        catch ( SignatureException e )
        {
            throw new CredentialException( e );
        }
    }
}
