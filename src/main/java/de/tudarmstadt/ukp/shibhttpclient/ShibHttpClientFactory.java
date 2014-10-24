package de.tudarmstadt.ukp.shibhttpclient;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.xml.parse.BasicParserPool;

import de.tudarmstadt.ukp.shibhttpclient.authentication.Authenticator;
import de.tudarmstadt.ukp.shibhttpclient.processor.EcpRequestPreProcessor;
import de.tudarmstadt.ukp.shibhttpclient.processor.EcpResponsePostProcessor;

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
    
    /**
     * Attach ECP interceptors to the given {@link HttpClientBuilder} using the specified idpUrl and {@link Authenticator}. A
     * {@link HttpClient} based on the current {@link HttpClientBuilder} configuration is used to send requests to IdP/SP.
     * 
     * @param clientBuilder
     *            the build for the ecp-intercepted {@link HttpClient}
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param authenticator
     *            the {@link Authenticator} to provide credentials to a {@link HttpRequest} (while logging in at the IdP.
     * @return a {@link HttpClientBuilder} based on the given configuration + ecp interceptors for transparent authentication.
     */
    public HttpClientBuilder attachEcpInterceptors( HttpClientBuilder clientBuilder, String idpUrl, Authenticator authenticator )
    {
        return attachEcpInterceptors( clientBuilder, clientBuilder.build(), idpUrl, authenticator );
    }
    
    /**
     * Attach ECP interceptors to the given {@link HttpClientBuilder} using the specified idpUrl and {@link Authenticator}.
     * 
     * @param clientBuilder
     *            the build for the ecp-intercepted {@link HttpClient}
     * @param ecpClient
     *            the {@link HttpClient} that is used to execute the transparent requests.
     * @param idpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param authenticator
     *            the {@link Authenticator} to provide credentials to a {@link HttpRequest} (while logging in at the IdP.
     * @return a {@link HttpClientBuilder} based on the given configuration + ecp interceptors for transparent authentication.
     */
    public HttpClientBuilder attachEcpInterceptors( HttpClientBuilder clientBuilder, HttpClient ecpClient, String idpUrl,
            Authenticator authenticator )
    {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware( true );
        
        EcpRequestPreProcessor preProcessor = new EcpRequestPreProcessor( ecpClient );
        EcpResponsePostProcessor postProcessor = new EcpResponsePostProcessor( ecpClient, parserPool, idpUrl, authenticator );
        
        return clientBuilder.addInterceptorFirst( preProcessor ).addInterceptorLast( postProcessor );
    }
}
