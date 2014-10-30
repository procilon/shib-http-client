package de.tudarmstadt.ukp.shibhttpclient.authentication;

import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpRequest;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.DirectoryString;

public class SenderVouchesAuthenticator implements Authenticator
{
    private String userId;
    
    public SenderVouchesAuthenticator( String userId )
    {
        this.userId = userId;
    }
    
    @Override
    public void supplyCredentials( HttpRequest request )
    {
        DirectoryString asn1UserId = new DirectoryString( userId );
        DERSequence token = new DERSequence( new ASN1Encodable[] { asn1UserId } );
        
        String senderVouchesHeader = "Sender-Voucher " + DatatypeConverter.printBase64Binary( token.getDEREncoded() );
        
        request.addHeader( AUTH_HEADER, senderVouchesHeader );
    }
    
}
