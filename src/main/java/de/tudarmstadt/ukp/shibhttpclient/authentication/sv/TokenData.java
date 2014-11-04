package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.text.ParseException;
import java.util.Date;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.DirectoryString;

public class TokenData implements DEREncodable
{
    private final String id;
    private final Date   validFrom;
    private final Date   validUntil;
    
    /**
     * @param id
     *            the user ID
     * @param validFrom
     *            the start of the token validity
     * @param validUntil
     *            the end of the token validity
     */
    public TokenData( String id, Date validFrom, Date validUntil )
    {
        this.id = id;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }
    
    @Override
    public DERObject getDERObject()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add( new DirectoryString( id ) );
        vector.add( new DERGeneralizedTime( validFrom ) );
        vector.add( new DERGeneralizedTime( validUntil ) );
        
        return new DERSequence( vector );
    }
    
    public static TokenData parse( ASN1Sequence sequence ) throws ParseException
    {
        if ( sequence.size() != 3 )
        {
            throw new IllegalArgumentException( "expected sequence of size 3" );
        }
        
        DEREncodable encodedId = sequence.getObjectAt( 0 );
        DEREncodable encodedValidFrom = sequence.getObjectAt( 1 );
        DEREncodable encodedValidUntil = sequence.getObjectAt( 2 );
        
        String id = DirectoryString.getInstance( encodedId ).getString();
        Date validFrom = DERGeneralizedTime.getInstance( encodedValidFrom ).getDate();
        Date validUntil = DERGeneralizedTime.getInstance( encodedValidUntil ).getDate();
        
        return new TokenData( id, validFrom, validUntil );
    }
    
    /**
     * Get the id.
     * 
     * @return the id
     */
    public String getId()
    {
        return id;
    }
    
    /**
     * Get the validFrom.
     * 
     * @return the validFrom
     */
    public Date getValidFrom()
    {
        return validFrom;
    }
    
    /**
     * Get the validUntil.
     * 
     * @return the validUntil
     */
    public Date getValidUntil()
    {
        return validUntil;
    }
    
    @Override
    public String toString()
    {
        return ToStringBuilder.reflectionToString( this, ToStringStyle.SHORT_PREFIX_STYLE );
    }
}
