package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

public class TokenData implements DEREncodable
{
    private final String    id;
    private final Set<Role> roles;
    private final Date      validFrom;
    private final Date      validUntil;
    
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
        this( id, Collections.<Role> emptySet(), validFrom, validUntil );
    }
    
    /**
     * @param id
     *            the user ID
     * @param roles
     *            the user roles
     * @param validFrom
     *            the start of the token validity
     * @param validUntil
     *            the end of the token validity
     */
    public TokenData( String id, Set<Role> roles, Date validFrom, Date validUntil )
    {
        this.id = id;
        this.roles = roles;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }
    
    @Override
    public DERObject getDERObject()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add( new DirectoryString( id ) );
        if ( !roles.isEmpty() )
        {
            ASN1EncodableVector rolesVector = new ASN1EncodableVector();
            for ( Role role : roles )
            {
                rolesVector.add( role );
            }
            vector.add( new DERTaggedObject( 0, new DERSet( rolesVector ) ) );
        }
        vector.add( new DERGeneralizedTime( validFrom ) );
        vector.add( new DERGeneralizedTime( validUntil ) );
        
        return new DERSequence( vector );
    }
    
    public static TokenData parse( ASN1Sequence sequence ) throws ParseException
    {
        if ( sequence.size() < 3 )
        {
            throw new IllegalArgumentException( "expected sequence of size 3" );
        }
        
        DEREncodable encodedId = sequence.getObjectAt( 0 );
        DEREncodable secondObject = sequence.getObjectAt( 1 );
        
        DEREncodable encodedValidFrom;
        DEREncodable encodedValidUntil;
        Set<Role> roles;
        if ( secondObject instanceof ASN1TaggedObject )
        {
            roles = parseRoles( secondObject );
            encodedValidFrom = sequence.getObjectAt( 2 );
            encodedValidUntil = sequence.getObjectAt( 3 );
        }
        else
        {
            encodedValidFrom = secondObject;
            encodedValidUntil = sequence.getObjectAt( 2 );
            roles = Collections.emptySet();
        }
        
        String id = DirectoryString.getInstance( encodedId ).getString();
        Date validFrom = DERGeneralizedTime.getInstance( encodedValidFrom ).getDate();
        Date validUntil = DERGeneralizedTime.getInstance( encodedValidUntil ).getDate();
        
        return new TokenData( id, roles, validFrom, validUntil );
    }
    
    private static Set<Role> parseRoles( DEREncodable secondObject )
    {
        Set<Role> roles;
        ASN1TaggedObject encodedRoles = (ASN1TaggedObject) secondObject;
        if ( encodedRoles.getTagNo() != 0 )
        {
            throw new IllegalArgumentException( "Unexpected tag number: " + encodedRoles.getTagNo() );
        }
        @SuppressWarnings( "unchecked" )
        Enumeration<ASN1Encodable> roleSet = ASN1Set.getInstance( encodedRoles.getObject() ).getObjects();
        roles = new HashSet<Role>();
        while ( roleSet.hasMoreElements() )
        {
            ASN1Encodable role = roleSet.nextElement();
            roles.add( Role.parse( ASN1Sequence.getInstance( role ) ) );
        }
        
        return Collections.unmodifiableSet( roles );
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
    
    /**
     * Get the roles.
     * 
     * @return the roles
     */
    public Set<Role> getRoles()
    {
        return roles;
    }
    
    @Override
    public String toString()
    {
        return ToStringBuilder.reflectionToString( this, ToStringStyle.SHORT_PREFIX_STYLE );
    }
}
