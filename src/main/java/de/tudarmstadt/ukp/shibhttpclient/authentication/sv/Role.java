package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.util.Enumeration;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * A user role.
 * 
 * @author fichtelmannm
 *
 */
public class Role implements DEREncodable
{
    private final String name;
    
    private final String application;
    private final String context;
    
    /**
     * Create a new {@link Role}.
     * 
     * @param name
     *            the name of the role
     */
    public Role( String name )
    {
        this( name, null, null );
    }
    
    /**
     * Create a new {@link Role}.
     * 
     * @param name
     *            the name of the role
     * @param application
     *            an optional application name with which the role is associated
     * @param context
     *            an optional context of the role association
     */
    public Role( String name, String application, String context )
    {
        this.name = name;
        this.application = application;
        this.context = context;
    }
    
    /**
     * Get the name.
     * 
     * @return the name
     */
    public String getName()
    {
        return name;
    }
    
    /**
     * Get the application.
     * 
     * @return the application
     */
    public String getApplication()
    {
        return application;
    }
    
    /**
     * Get the context.
     * 
     * @return the context
     */
    public String getContext()
    {
        return context;
    }
    
    @Override
    public DERObject getDERObject()
    {
        ASN1EncodableVector sequence = new ASN1EncodableVector();
        sequence.add( new DirectoryString( name ) );
        if ( null != application )
        {
            sequence.add( new DERTaggedObject( 0, new DirectoryString( application ) ) );
        }
        if ( null != context )
        {
            sequence.add( new DERTaggedObject( 1, new DirectoryString( context ) ) );
        }
        
        return new DERSequence( sequence );
    }
    
    public static Role parse( ASN1Sequence sequence )
    {
        DEREncodable nameData = sequence.getObjectAt( 0 );
        String name = DirectoryString.getInstance( nameData ).getString();
        
        String application = null;
        String context = null;
        if ( sequence.size() > 1 )
        {
            @SuppressWarnings( "unchecked" )
            Enumeration<ASN1Encodable> objects = sequence.getObjects();
            while ( objects.hasMoreElements() )
            {
                ASN1Encodable encodable = objects.nextElement();
                
                if ( encodable instanceof ASN1TaggedObject )
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject) encodable;
                    switch ( tagged.getTagNo() )
                    {
                    case 0:
                        application = DirectoryString.getInstance( tagged.getObject() ).getString();
                        break;
                    case 1:
                        context = DirectoryString.getInstance( tagged.getObject() ).getString();
                        break;
                    default:
                        throw new IllegalArgumentException( "Unknown tag number: " + tagged.getTagNo() );
                    }
                }
            }
        }
        
        return new Role( name, application, context );
    }
    
    @Override
    public String toString()
    {
        return ToStringBuilder.reflectionToString( this, ToStringStyle.SHORT_PREFIX_STYLE );
    }
}
