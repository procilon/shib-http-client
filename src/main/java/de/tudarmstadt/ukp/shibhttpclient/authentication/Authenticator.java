package de.tudarmstadt.ukp.shibhttpclient.authentication;

import org.apache.http.HttpRequest;

/**
 * An interface to supply authentication headers to HTTP requests.
 * 
 * @author fichtelmannm
 *
 */
public interface Authenticator
{
    String AUTH_HEADER = "Authorization";
    
    /**
     * Adds authentication headers to the given request.
     * 
     * @param request
     */
    void supplyCredentials( HttpRequest request );
}
