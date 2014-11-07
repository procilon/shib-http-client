package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.text.ParseException;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;

public class SignedToken implements DEREncodable
{
    private final TokenData           data;
    private final IssuerSerial        signer;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final byte[]              signature;
    
    /**
     * @param data
     *            the signed token data
     * @param signer
     * @param signatureAlgorithm
     * @param signature
     */
    public SignedToken( TokenData data, IssuerSerial signer, AlgorithmIdentifier signatureAlgorithm, byte[] signature )
    {
        this.data = data;
        this.signer = signer;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }
    
    @Override
    public DERObject getDERObject()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add( data );
        vector.add( signer );
        vector.add( signatureAlgorithm );
        vector.add( new DEROctetString( signature ) );
        
        return new DERSequence( vector );
    }
    
    public static SignedToken parse( ASN1Sequence sequence ) throws ParseException
    {
        if ( sequence.size() != 4 )
        {
            throw new IllegalArgumentException( "expected sequence of size 4" );
        }
        
        DEREncodable encodedData = sequence.getObjectAt( 0 );
        DEREncodable encodedSigner = sequence.getObjectAt( 1 );
        DEREncodable encodedAlgorithm = sequence.getObjectAt( 2 );
        DEREncodable encodedSignature = sequence.getObjectAt( 3 );
        
        TokenData data = TokenData.parse( DERSequence.getInstance( encodedData ) );
        IssuerSerial signer = IssuerSerial.getInstance( encodedSigner );
        AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance( encodedAlgorithm );
        byte[] signature = DEROctetString.getInstance( encodedSignature ).getOctets();
        
        return new SignedToken( data, signer, algorithm, signature );
    }
    
    /**
     * Get the data.
     * 
     * @return the data
     */
    public TokenData getData()
    {
        return data;
    }
    
    /**
     * Get the signer.
     * 
     * @return the signer
     */
    public IssuerSerial getSigner()
    {
        return signer;
    }
    
    /**
     * Get the signatureAlgorithm.
     * 
     * @return the signatureAlgorithm
     */
    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }
    
    /**
     * Get the signature.
     * 
     * @return the signature
     */
    public byte[] getSignature()
    {
        return signature;
    }
    
    @Override
    public String toString()
    {
        return ToStringBuilder.reflectionToString( this, ToStringStyle.SHORT_PREFIX_STYLE );
    }
}
