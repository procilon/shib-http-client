package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
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
    
}
