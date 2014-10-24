package de.tudarmstadt.ukp.shibhttpclient.processor;

import static de.tudarmstadt.ukp.shibhttpclient.Utils.*;
import static java.util.Arrays.asList;

import java.io.IOException;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.NonRepeatableRequestException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml2.ecp.Response;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.soap.soap11.impl.HeaderBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.Base64;

import de.tudarmstadt.ukp.shibhttpclient.ShibHttpClient;

/**
 * Analyse responses to detect PAOS solicitations for an authentication. Answer these and then transparently proceed with the original
 * request.
 */
public class EcpResponsePostProcessor implements HttpResponseInterceptor
{
    private final Log                 log              = LogFactory.getLog( getClass() );
    
    private static final String       MIME_TYPE_PAOS   = "application/vnd.paos+xml";
    private static final String       HEADER_PAOS      = "PAOS";
    private static final List<String> REDIRECTABLE     = asList( "HEAD", "GET", "CONNECT" );
    private static final String       AUTH_IN_PROGRESS = ShibHttpClient.class.getName() + ".AUTH_IN_PROGRESS";
    
    private final HttpClient          client;
    private final ParserPool          parserPool;
    private final String              idpUrl;
    private final String              username;
    private final String              password;
    
    public EcpResponsePostProcessor( HttpClient client, ParserPool parserPool, String idpUrl, String username, String password )
    {
        this.client = client;
        this.parserPool = parserPool;
        this.idpUrl = idpUrl;
        this.username = username;
        this.password = password;
    }
    
    @Override
    public void process( HttpResponse res, HttpContext ctx ) throws HttpException, IOException
    {
        HttpRequest originalRequest;
        // check for RequestWrapper objects, retrieve the original request
        if ( ctx.getAttribute( "http.request" ) instanceof HttpRequestWrapper )
        { // does not forward request to original
            log.trace( "RequestWrapper found" );
            originalRequest = (HttpRequest) ((HttpRequestWrapper) ctx.getAttribute( "http.request" )).getOriginal();
        }
        else
        { // use a basic HttpRequest because BasicHttpRequest objects cannot be recast to HttpUriRequest objects
            originalRequest = (HttpRequest) ctx.getAttribute( "http.request" );
        }
        
        log.trace( "Accessing [" + originalRequest.getRequestLine().getUri() + " " + originalRequest.getRequestLine().getMethod() + "]" );
        
        // -- Check if authentication is already in progress ----------------------------------
        if ( res.getParams().isParameterTrue( AUTH_IN_PROGRESS ) )
        {
            log.trace( "Authentication in progress -- skipping post processor" );
            return;
        }
        
        // -- Check if authentication is necessary --------------------------------------------
        if ( !isSamlSoapResponse( res ) )
        {
            return;
        }
        
        log.trace( "Detected login request" );
        
        // -- If the request was a HEAD request, we need to try again using a GET request ----
        HttpResponse paosResponse = res;
        if ( originalRequest.getRequestLine().getMethod() == "HEAD" )
        {
            log.trace( "Original request was a HEAD, restarting authenticiation with GET" );
            
            HttpGet authTriggerRequest = new HttpGet( originalRequest.getRequestLine().getUri() );
            authTriggerRequest.getParams().setBooleanParameter( AUTH_IN_PROGRESS, true );
            paosResponse = client.execute( authTriggerRequest );
        }
        
        // -- Parse PAOS response -------------------------------------------------------------
        Envelope initialLoginSoapResponse = getSoapMessage( paosResponse.getEntity() );
        
        // -- Capture relay state (optional) --------------------------------------------------
        RelayState relayState = captureRelayState( initialLoginSoapResponse );
        
        // -- Capture response consumer -------------------------------------------------------
        // // pick out the responseConsumerURL attribute value from the SP response so that
        // // it can later be compared to the assertionConsumerURL sent from the IdP
        // String responseConsumerURL = ((XSAny) initialLoginSoapResponse.getHeader()
        // .getUnknownXMLObjects(E_PAOS_REQUEST).get(0)).getUnknownAttributes().get(
        // A_RESPONSE_CONSUMER_URL);
        // log.debug("responseConsumerURL: [" + responseConsumerURL + "]");
        
        // -- Send log-in request to the IdP --------------------------------------------------
        // Prepare the request to the IdP
        log.debug( "Logging in to IdP [" + idpUrl + "]" );
        Envelope idpLoginSoapRequest = new EnvelopeBuilder().buildObject();
        Body b = initialLoginSoapResponse.getBody();
        b.detach();
        idpLoginSoapRequest.setBody( b );
        
        // Try logging in to the IdP using HTTP BASIC authentication
        HttpPost idpLoginRequest = new HttpPost( idpUrl );
        idpLoginRequest.getParams().setBooleanParameter( AUTH_IN_PROGRESS, true );
        idpLoginRequest.addHeader( HttpHeaders.AUTHORIZATION, "Basic " + Base64.encodeBytes( (username + ":" + password).getBytes() ) );
        idpLoginRequest.setEntity( new StringEntity( xmlToString( idpLoginSoapRequest ) ) );
        HttpResponse idpLoginResponse = client.execute( idpLoginRequest );
        
        // -- Handle log-in response from the IdP ---------------------------------------------
        log.debug( "Status: " + idpLoginResponse.getStatusLine() );
        if ( idpLoginResponse.getStatusLine().getStatusCode() != 200 )
        {
            throw new AuthenticationException( idpLoginResponse.getStatusLine().toString() );
        }
        
        Envelope idpLoginSoapResponse = getSoapMessage( idpLoginResponse.getEntity() );
        String assertionConsumerServiceURL = ((Response) idpLoginSoapResponse.getHeader()
                .getUnknownXMLObjects( Response.DEFAULT_ELEMENT_NAME ).get( 0 )).getAssertionConsumerServiceURL();
        log.debug( "assertionConsumerServiceURL: " + assertionConsumerServiceURL );
        
        List<XMLObject> responses = idpLoginSoapResponse.getBody().getUnknownXMLObjects(
                org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME );
        if ( !responses.isEmpty() )
        {
            org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) responses.get( 0 );
            
            // Get root code (?)
            StatusCode sc = response.getStatus().getStatusCode();
            while ( sc.getStatusCode() != null )
            {
                sc = sc.getStatusCode();
            }
            
            // Hm, they don't like us
            if ( StatusCode.AUTHN_FAILED_URI.equals( sc.getValue() ) )
            {
                throw new AuthenticationException( sc.getValue() );
            }
        }
        
        // compare the responseConsumerURL from the SP to the assertionConsumerServiceURL from
        // the IdP and if they are not identical then send a SOAP fault to the SP
        // if (false) {
        // // Nice guys should send a fault to the SP - we are NOT nice yet
        // }
        
        // -- Forward ticket to the SP --------------------------------------------------------
        // craft the package to send to the SP by copying the response from the IdP but
        // removing the SOAP header sent by the IdP and instead putting in a new header that
        // includes the relay state sent by the SP
        Header header = new HeaderBuilder().buildObject();
        header.getUnknownXMLObjects().clear();
        if ( relayState != null )
        {
            header.getUnknownXMLObjects().add( relayState );
        }
        idpLoginSoapResponse.setHeader( header );
        
        // push the response to the SP at the assertion consumer service URL included in
        // the response from the IdP
        log.debug( "Logging in to SP" );
        HttpPost spLoginRequest = new HttpPost( assertionConsumerServiceURL );
        spLoginRequest.getParams().setBooleanParameter( AUTH_IN_PROGRESS, true );
        spLoginRequest.setHeader( HttpHeaders.CONTENT_TYPE, MIME_TYPE_PAOS );
        spLoginRequest.setEntity( new StringEntity( xmlToString( idpLoginSoapResponse ) ) );
        HttpClientParams.setRedirecting( spLoginRequest.getParams(), false );
        HttpResponse spLoginResponse = client.execute( spLoginRequest );
        log.debug( "Status: " + spLoginResponse.getStatusLine() );
        log.debug( "Authentication complete" );
        
        // -- Handle unredirectable cases -----------------------------------------------------
        // If we get a redirection and the request is redirectable, then let the client redirect
        // If the request is not redirectable, signal that the operation must be retried.
        if ( spLoginResponse.getStatusLine().getStatusCode() == 302
                && !REDIRECTABLE.contains( originalRequest.getRequestLine().getMethod() ) )
        {
            EntityUtils.consume( spLoginResponse.getEntity() );
            throw new NonRepeatableRequestException( "Request of type [" + originalRequest.getRequestLine().getMethod()
                    + "] cannot be redirected" );
        }
        
        // -- Transparently return response to original request -------------------------------
        // Return response received after login as actual response to original caller
        res.setEntity( spLoginResponse.getEntity() );
        res.setHeaders( spLoginResponse.getAllHeaders() );
        res.setStatusLine( spLoginResponse.getStatusLine() );
    }
    
    /**
     * Checks whether the HttpResponse is a SAML SOAP message
     * 
     * @param res
     *            the HttpResponse to check
     * @return true if the HttpResponse is a SAML SOAP message, false if not
     */
    private boolean isSamlSoapResponse( HttpResponse res )
    {
        boolean isSamlSoap = false;
        if ( res.getFirstHeader( HttpHeaders.CONTENT_TYPE ) != null )
        {
            ContentType contentType = ContentType.parse( res.getFirstHeader( HttpHeaders.CONTENT_TYPE ).getValue() );
            isSamlSoap = MIME_TYPE_PAOS.equals( contentType.getMimeType() );
        }
        return isSamlSoap;
    }
    
    /**
     * Extracts the SOAP message from the HttpResponse
     * 
     * @param entity
     *            the HttpEntity to retrieve the SOAP message from
     * @return soapEnvelope the SOAP message
     * @throws IOException
     * @throws IllegalStateException
     * @throws ClientProtocolException
     */
    private org.opensaml.ws.soap.soap11.Envelope getSoapMessage( HttpEntity entity ) throws ClientProtocolException, IllegalStateException,
            IOException
    {
        Envelope soapEnvelope = (Envelope) unmarshallMessage( parserPool, entity.getContent() );
        EntityUtils.consumeQuietly( entity );
        return soapEnvelope;
    }
    
    /**
     * Captures the ECP relay state in a SAML SOAP message
     * 
     * @param soapEnvelope
     *            the SOAP message to check for the ECP relay state
     * @return relayState the ECP relay state in the SOAP message
     */
    private org.opensaml.saml2.ecp.RelayState captureRelayState( org.opensaml.ws.soap.soap11.Envelope soapEnvelope )
    {
        RelayState relayState = null;
        if ( !soapEnvelope.getHeader().getUnknownXMLObjects( RelayState.DEFAULT_ELEMENT_NAME ).isEmpty() )
        {
            relayState = (RelayState) soapEnvelope.getHeader().getUnknownXMLObjects( RelayState.DEFAULT_ELEMENT_NAME ).get( 0 );
            relayState.detach();
            log.trace( "Relay state: captured" );
        }
        return relayState;
    }
}
