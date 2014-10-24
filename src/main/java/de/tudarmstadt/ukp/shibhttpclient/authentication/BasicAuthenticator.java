package de.tudarmstadt.ukp.shibhttpclient.authentication;

import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpRequest;

public class BasicAuthenticator implements Authenticator
{
    private String username;
    private char[] password;
    
    public BasicAuthenticator( String username, char[] password )
    {
        this.username = username;
        this.password = password;
    }
    
    @Override
    public void supplyCredentials( HttpRequest request )
    {
        String encodedCredentials = encodeCredentials();
        
        String basicAuth = "Basic " + encodedCredentials;
        
        request.addHeader( AUTH_HEADER, basicAuth );
    }
    
    private String encodeCredentials()
    {
        String credentials = username + ":" + new String( password );
        
        return DatatypeConverter.printBase64Binary( credentials.getBytes() );
    }
}
