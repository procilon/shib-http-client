package de.tudarmstadt.ukp.shibhttpclient.processor;

import static de.tudarmstadt.ukp.shibhttpclient.processor.EcpResponsePostProcessor.*;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.protocol.HttpContext;
import org.opensaml.common.xml.SAMLConstants;

/**
 * Add the ECP/PAOS headers to each outgoing request.
 */
public class EcpRequestPreProcessor implements HttpRequestInterceptor
{
    private final Log           log         = LogFactory.getLog( getClass() );
    
    private static final String HEADER_PAOS = "PAOS";
    
    private final HttpClient    client;
    
    public EcpRequestPreProcessor( HttpClient client )
    {
        this.client = client;
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
        @SuppressWarnings( "deprecation" )
        boolean authNotInProgress = r.getParams().isParameterFalse( AUTH_IN_PROGRESS );
        if ( !REDIRECTABLE.contains( r.getRequestLine().getMethod() ) && authNotInProgress )
        {
            // && !r.getRequestLine().getUri().startsWith(idpUrl)) {
            log.trace( "Unredirectable request [" + r.getRequestLine().getMethod() + "], trying to knock first at "
                    + r.getRequestLine().getUri() );
            HttpHead knockRequest = new HttpHead( r.getRequestLine().getUri() );
            client.execute( knockRequest );
            
            log.trace( "Knocked" );
        }
    }
    
}
