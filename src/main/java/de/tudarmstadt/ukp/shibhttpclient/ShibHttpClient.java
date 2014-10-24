/*******************************************************************************
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * For copyright information, see NOTICE.txt file.
 ******************************************************************************/

package de.tudarmstadt.ukp.shibhttpclient;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.net.ProxySelector;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.opensaml.xml.parse.BasicParserPool;

import de.tudarmstadt.ukp.shibhttpclient.authentication.Authenticator;
import de.tudarmstadt.ukp.shibhttpclient.authentication.BasicAuthenticator;
import de.tudarmstadt.ukp.shibhttpclient.processor.EcpRequestPreProcessor;
import de.tudarmstadt.ukp.shibhttpclient.processor.EcpResponsePostProcessor;

// deprecated classes we should try to find alternatives for

/**
 * Simple Shibbolethized {@link HttpClient} using basic HTTP username/password authentication to authenticate against a predefined IdP. The
 * client indicates its ECP capability to the SP. Authentication happens automatically if the SP replies to any requesting using a PAOS
 * authentication solicitation.
 * <p>
 * GET and HEAD requests work completely transparent using redirection. If another request is performed, the client tries a HEAD request to
 * the specified URL first. If this results in an authentication request, a login is performed before the original request is executed.
 */
@SuppressWarnings( "deprecation" )
public class ShibHttpClient implements HttpClient
{
    private final Log                 log              = LogFactory.getLog( getClass() );
    
    private static final String       AUTH_IN_PROGRESS = ShibHttpClient.class.getName() + ".AUTH_IN_PROGRESS";
    
    private static final String       MIME_TYPE_PAOS   = "application/vnd.paos+xml";
    
    private static final String       HEADER_PAOS      = "PAOS";
    
    private CloseableHttpClient       client;
    
    private BasicCookieStore          cookieStore;
    
    private String                    idpUrl;
    
    private String                    username;
    
    private String                    password;
    
    private BasicParserPool           parserPool;
    
    private static final List<String> REDIRECTABLE     = asList( "HEAD", "GET", "CONNECT" );
    
    /**
     * Create a new client (assuming we don't accept self-signed certificates)
     * 
     * @param aIdpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param aUsername
     *            the user name to log into the IdP.
     * @param aPassword
     *            the password to log in to the IdP.
     */
    public ShibHttpClient( String aIdpUrl, String aUsername, String aPassword )
    {
        // construct ourselves with our abbreviated set of parameters
        this( aIdpUrl, aUsername, aPassword, false );
    }
    
    /**
     * Create a new client (assuming we don't need a proxy)
     * 
     * @param aIdpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param aUsername
     *            the user name to log into the IdP.
     * @param aPassword
     *            the password to log in to the IdP.
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     */
    public ShibHttpClient( String aIdpUrl, String aUsername, String aPassword, boolean anyCert )
    {
        // construct ourselves with our abbreviated set of parameters
        this( aIdpUrl, aUsername, aPassword, null, anyCert );
    }
    
    /**
     * Create a new client (with an explicit proxy)
     * 
     * @param aIdpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param aUsername
     *            the user name to log into the IdP.
     * @param aPassword
     *            the password to log in to the IdP.
     * @param aProxy
     *            if not {@code null}, use this proxy instead of the default system proxy (if any)
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     */
    public ShibHttpClient( String aIdpUrl, String aUsername, String aPassword, HttpHost aProxy, boolean anyCert )
    {
        // construct ourselves with our abbreviated set of parameters
        this( aIdpUrl, aUsername, aPassword, aProxy, anyCert, true );
    }
    
    /**
     * Create a new client (with an explicit proxy and possibly transparent authentication)
     * 
     * @param aIdpUrl
     *            the URL of the IdP. Should probably be something ending in "/SAML2/SOAP/ECP"
     * @param aUsername
     *            the user name to log into the IdP.
     * @param aPassword
     *            the password to log in to the IdP.
     * @param aProxy
     *            if not {@code null}, use this proxy instead of the default system proxy (if any)
     * @param anyCert
     *            if {@code true}, accept any certificate from any remote host. Otherwise, certificates need to be installed in the JRE.
     * @param transparentAuth
     *            if {@code true} (default), add a HttpRequestPostProcessor to transparently authenticate. Otherwise, you must handle the
     *            authentication process yourself.
     */
    public ShibHttpClient( String aIdpUrl, String aUsername, String aPassword, HttpHost aProxy, boolean anyCert, boolean transparentAuth )
    {
        
        setIdpUrl( aIdpUrl );
        setUsername( aUsername );
        setPassword( aPassword );
        
        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware( true );
        
        // Use a pooling connection manager, because we'll have to do a call out to the IdP
        // while still being in a connection with the SP
        PoolingHttpClientConnectionManager connMgr;
        if ( anyCert )
        {
            try
            {
                SSLContextBuilder builder = new SSLContextBuilder();
                TrustStrategy trustStrategy = new TrustStrategy()
                {
                    @Override
                    public boolean isTrusted( X509Certificate[] chain, String authType ) throws CertificateException
                    {
                        return true;
                    }
                };
                builder.loadTrustMaterial( null, trustStrategy );
                Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
                        .<ConnectionSocketFactory> create()
                        .register( "http", new PlainConnectionSocketFactory() )
                        .register( "https",
                                new SSLConnectionSocketFactory( builder.build(), SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER ) )
                        .build();
                connMgr = new PoolingHttpClientConnectionManager( socketFactoryRegistry );
            }
            catch ( GeneralSecurityException e )
            {
                // There shouldn't be any of these exceptions, because we do not use an actual
                // keystore
                throw new IllegalStateException( e );
            }
        }
        else
        {
            connMgr = new PoolingHttpClientConnectionManager();
        }
        connMgr.setMaxTotal( 10 );
        connMgr.setDefaultMaxPerRoute( 5 );
        
        // The client needs to remember the auth cookie
        cookieStore = new BasicCookieStore();
        RequestConfig globalRequestConfig = RequestConfig.custom().setCookieSpec( CookieSpecs.BROWSER_COMPATIBILITY ).build();
        
        // Let's throw all common client elements into one builder object
        HttpClientBuilder customClient = HttpClients.custom().setConnectionManager( connMgr )
        // The client needs to remember the auth cookie
                .setDefaultRequestConfig( globalRequestConfig ).setDefaultCookieStore( cookieStore );
        
        // Build the client with/without proxy settings
        if ( aProxy == null )
        {
            // use the proxy settings of the JVM, if specified
            customClient = customClient.setRoutePlanner( new SystemDefaultRoutePlanner( ProxySelector.getDefault() ) );
        }
        else
        {
            // use the explicit proxy
            customClient = customClient.setProxy( aProxy );
        }
        
        HttpClient ecpClient = customClient.build();
        
        // Add the ECP/PAOS headers - needs to be added first so the cookie we get from
        // the authentication can be handled by the RequestAddCookies interceptor later
        customClient = customClient.addInterceptorFirst( new EcpRequestPreProcessor( ecpClient, cookieStore ) );
        
        // Automatically log into IdP if transparent Shibboleth authentication handling is requested (default)
        if ( transparentAuth )
        {
            Authenticator basicAuthenticator = new BasicAuthenticator( aUsername, aPassword.toCharArray() );
            customClient = customClient.addInterceptorFirst( new EcpResponsePostProcessor( ecpClient, parserPool, aIdpUrl,
                    basicAuthenticator ) );
        }
        
        client = customClient.build();
    }
    
    public void setIdpUrl( String aIdpUrl )
    {
        idpUrl = aIdpUrl;
    }
    
    public void setUsername( String aUsername )
    {
        username = aUsername;
    }
    
    public void setPassword( String aPassword )
    {
        password = aPassword;
    }
    
    protected static String getAuthInProgress()
    {
        return AUTH_IN_PROGRESS;
    }
    
    @Override
    public HttpParams getParams()
    {
        return client.getParams();
    }
    
    @Override
    public ClientConnectionManager getConnectionManager()
    {
        return client.getConnectionManager();
    }
    
    @Override
    public HttpResponse execute( HttpUriRequest aRequest ) throws IOException, ClientProtocolException
    {
        return client.execute( aRequest );
    }
    
    @Override
    public HttpResponse execute( HttpUriRequest aRequest, HttpContext aContext ) throws IOException, ClientProtocolException
    {
        return client.execute( aRequest, aContext );
    }
    
    @Override
    public HttpResponse execute( HttpHost aTarget, HttpRequest aRequest ) throws IOException, ClientProtocolException
    {
        return client.execute( aTarget, aRequest );
    }
    
    @Override
    public HttpResponse execute( HttpHost aTarget, HttpRequest aRequest, HttpContext aContext ) throws IOException, ClientProtocolException
    {
        return client.execute( aTarget, aRequest, aContext );
    }
    
    @Override
    public <T> T execute( HttpUriRequest aRequest, ResponseHandler<? extends T> aResponseHandler ) throws IOException,
            ClientProtocolException
    {
        return client.execute( aRequest, aResponseHandler );
    }
    
    @Override
    public <T> T execute( HttpUriRequest aRequest, ResponseHandler<? extends T> aResponseHandler, HttpContext aContext )
            throws IOException, ClientProtocolException
    {
        return client.execute( aRequest, aResponseHandler, aContext );
    }
    
    @Override
    public <T> T execute( HttpHost aTarget, HttpRequest aRequest, ResponseHandler<? extends T> aResponseHandler ) throws IOException,
            ClientProtocolException
    {
        return client.execute( aTarget, aRequest, aResponseHandler );
    }
    
    @Override
    public <T> T execute( HttpHost aTarget, HttpRequest aRequest, ResponseHandler<? extends T> aResponseHandler, HttpContext aContext )
            throws IOException, ClientProtocolException
    {
        return client.execute( aTarget, aRequest, aResponseHandler, aContext );
    }
}
