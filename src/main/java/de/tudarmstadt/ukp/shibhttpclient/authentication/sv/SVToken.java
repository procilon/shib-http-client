package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;

public class SVToken implements DEREncodable
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
    public SVToken( TokenData data, IssuerSerial signer, AlgorithmIdentifier signatureAlgorithm, byte[] signature )
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
}
