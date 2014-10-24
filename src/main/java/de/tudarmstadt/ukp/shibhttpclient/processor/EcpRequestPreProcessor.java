package de.tudarmstadt.ukp.shibhttpclient.processor;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.cookie.Cookie;
import org.apache.http.protocol.HttpContext;
import org.opensaml.common.xml.SAMLConstants;

import de.tudarmstadt.ukp.shibhttpclient.ShibHttpClient;

/**
 * Add the ECP/PAOS headers to each outgoing request.
 */
public class EcpRequestPreProcessor implements HttpRequestInterceptor
{
    private final Log                 log              = LogFactory.getLog( getClass() );
    
    private static final String       MIME_TYPE_PAOS   = "application/vnd.paos+xml";
    private static final String       HEADER_PAOS      = "PAOS";
    private static final List<String> REDIRECTABLE     = asList( "HEAD", "GET", "CONNECT" );
    private static final String       AUTH_IN_PROGRESS = ShibHttpClient.class.getName() + ".AUTH_IN_PROGRESS";
    
    private final HttpClient          client;
    private final CookieStore         cookieStore;
    
    public EcpRequestPreProcessor( HttpClient client )
    {
        this( client, null );
    }
    
    public EcpRequestPreProcessor( HttpClient client, CookieStore cookieStore )
    {
        this.client = client;
        this.cookieStore = cookieStore;
    }
    
    @Override
    public void process( HttpRequest request, HttpContext context ) throws HttpException, IOException
    {
        request.addHeader( HttpHeaders.ACCEPT, MIME_TYPE_PAOS );
        request.addHeader( HEADER_PAOS, "ver=\"" + SAMLConstants.PAOS_NS + "\";\"" + SAMLConstants.SAML20ECP_NS + "\"" );
        
        HttpRequest r = request;
        if ( request instanceof HttpRequestWrapper )
        { // does not forward request to original
            r = ((HttpRequestWrapper) request).getOriginal();
        }
        
        // This request is not redirectable, so we better knock to see if authentication
        // is necessary.
        if ( !REDIRECTABLE.contains( r.getRequestLine().getMethod() ) && r.getParams().isParameterFalse( AUTH_IN_PROGRESS ) )
        {
            // && !r.getRequestLine().getUri().startsWith(idpUrl)) {
            log.trace( "Unredirectable request [" + r.getRequestLine().getMethod() + "], trying to knock first at "
                    + r.getRequestLine().getUri() );
            HttpHead knockRequest = new HttpHead( r.getRequestLine().getUri() );
            client.execute( knockRequest );
            
            if ( cookieStore != null )
            {
                for ( Cookie c : cookieStore.getCookies() )
                {
                    log.trace( c.toString() );
                }
            }
            log.trace( "Knocked" );
        }
    }
    
}
