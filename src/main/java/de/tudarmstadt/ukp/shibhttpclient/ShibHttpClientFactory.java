package de.tudarmstadt.ukp.shibhttpclient;

import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;

public class ShibHttpClientFactory
{
    /**
     * Create a new {@link HttpClient} with ECP detection and transparent authentication. It uses the JRE truststore to verify secure
     * connections and the default system proxy configuration (if any).
     * 
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param username
     *            the user name to log into the IdP.
     * @param password
     *            the password to log in to the IdP.
     * @return a new {@link HttpClient} with ECP detection and transparent authentication.
     */
    public HttpClient create( String idpUrl, String username, String password )
    {
        return create( idpUrl, username, password, null );
    }
    
    /**
     * Create a new {@link HttpClient} with ECP detection and transparent authentication. It uses the default system proxy configuration (if
     * any).
     * 
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param username
     *            the user name to log into the IdP.
     * @param password
     *            the password to log in to the IdP.
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     * @return a new {@link HttpClient} with ECP detection and transparent authentication.
     */
    public HttpClient create( String idpUrl, String username, String password, boolean anyCert )
    {
        return create( idpUrl, username, password, null, anyCert, true );
    }
    
    /**
     * Create a new {@link HttpClient} with ECP detection and transparent authentication. It uses the JRE truststore to verify secure
     * connections.
     * 
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param username
     *            the user name to log into the IdP.
     * @param password
     *            the password to log in to the IdP.
     * @param proxy
     *            if not {@code null}, use this proxy instead of the default system proxy (if any)
     * @return a new {@link HttpClient} with ECP detection and transparent authentication.
     */
    public HttpClient create( String idpUrl, String username, String password, HttpHost proxy )
    {
        return create( idpUrl, username, password, proxy, false );
    }
    
    /**
     * Create a new {@link HttpClient} with ECP detection and transparent authentication.
     * 
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param username
     *            the user name to log into the IdP.
     * @param password
     *            the password to log in to the IdP.
     * @param proxy
     *            if not {@code null}, use this proxy instead of the default system proxy (if any)
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     * @return a new {@link HttpClient} with ECP detection and transparent authentication.
     */
    public HttpClient create( String idpUrl, String username, String password, HttpHost proxy, boolean anyCert )
    {
        return create( idpUrl, username, password, proxy, anyCert, true );
    }
    
    /**
     * Create a new {@link HttpClient} with ECP detection and transparent authentication if enabled.
     * 
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param username
     *            the user name to log into the IdP.
     * @param password
     *            the password to log in to the IdP.
     * @param proxy
     *            if not {@code null}, use this proxy instead of the default system proxy (if any)
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     * @param transparentAuth
     *            if {@code true}, handle authentication transparently. Otherwise, you must handle the authentication process yourself.
     * @return a new {@link HttpClient} with ECP detection and transparent authentication if enabled.
     */
    public HttpClient create( String idpUrl, String username, String password, HttpHost proxy, boolean anyCert, boolean transparentAuth )
    {
        return new ShibHttpClient( idpUrl, username, password, proxy, anyCert, transparentAuth );
    }
}
