package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.Predicate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

/**
 * Creates signed Sender-vouches tokens for intermediate authentication and authorization.
 * 
 * <p>
 * Sender-vouches is intended to let services act as a user. This enables a complex multi-tiered service infrastructure that retains
 * user-based restrictions.
 * </p>
 * 
 * @author max.fichtelmann@procilon.de
 *
 */
public class TokenSigner
{
    private static final AlgorithmIdentifier SIGNATURE_ALGORITHM;
    static
    {
        ASN1ObjectIdentifier rsaSsaPss = PKCSObjectIdentifiers.id_RSASSA_PSS;
        
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier( NISTObjectIdentifiers.id_sha256 );
        AlgorithmIdentifier mgfAlgorithm = new AlgorithmIdentifier( PKCSObjectIdentifiers.id_mgf1, digestAlgorithm );
        DERInteger saltLength = new DERInteger( 32 ); // SHA-256 digest size
        
        DEREncodable pssParameters = new RSASSAPSSparams( digestAlgorithm, mgfAlgorithm, saltLength, RSASSAPSSparams.DEFAULT_TRAILER_FIELD );
        
        SIGNATURE_ALGORITHM = new AlgorithmIdentifier( rsaSsaPss, pssParameters );
    }
    
    private final RSAPrivateKey              privateKey;
    private final X509Certificate            certificate;
    private final SecureRandom               rng;
    
    private CipherParameters                 parameters;
    private IssuerSerial                     issuerSerial;
    
    /**
     * Create a new {@link TokenSigner} with the specified keys.
     * 
     * @param privateKey
     * @param certificate
     */
    public TokenSigner( RSAPrivateKey privateKey, X509Certificate certificate )
    {
        this( privateKey, certificate, null );
    }
    
    /**
     * Create a new {@link TokenSigner} with the specified keys and an optional random number generator.
     * 
     * @param privateKey
     * @param certificate
     * @param rng
     */
    public TokenSigner( RSAPrivateKey privateKey, X509Certificate certificate, SecureRandom rng )
    {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.rng = rng;
    }
    
    /**
     * Create a signed token for the given userId with the specified validity constraints.
     * 
     * @param userId
     * @param validFrom
     * @param validUntil
     * @return
     * @throws SignatureException
     */
    public SignedToken createSignedToken( String userId, Date validFrom, Date validUntil ) throws SignatureException
    {
        return sign( new TokenData( userId, validFrom, validUntil ) );
    }
    
    /**
     * Sign the token data and create the signed sender-vouches token.
     * 
     * @param data
     * @return
     * @throws SignatureException
     */
    public SignedToken sign( TokenData data ) throws SignatureException
    {
        byte[] encoded = data.getDERObject().getDEREncoded();
        
        SHA256Digest digest = new SHA256Digest();
        PSSSigner signer = new PSSSigner( new RSABlindedEngine(), digest, digest.getDigestSize() );
        signer.init( true, parameters() );
        
        digest.update( encoded, 0, encoded.length );
        
        try
        {
            byte[] signature = signer.generateSignature();
            
            IssuerSerial issuerSerial = issuerSerial();
            
            return new SignedToken( data, issuerSerial, SIGNATURE_ALGORITHM, signature );
        }
        catch ( Exception e )
        {
            throw new SignatureException( e );
        }
    }
    
    public static boolean verify( SignedToken token, Collection<X509Certificate> trustedCertificates ) throws IssuerNotTrustedException
    {
        X509Certificate signerCertificate = findCertificate( trustedCertificates, token.getSigner() );
        if ( signerCertificate == null )
        {
            throw new IssuerNotTrustedException();
        }
        RSAPublicKey publicKey = (RSAPublicKey) signerCertificate.getPublicKey();
        
        byte[] signedData = token.getData().getDERObject().getDEREncoded();
        
        SHA256Digest digest = new SHA256Digest();
        PSSSigner verifier = new PSSSigner( new RSABlindedEngine(), digest, digest.getDigestSize() );
        verifier.init( false, new RSAKeyParameters( false, publicKey.getModulus(), publicKey.getPublicExponent() ) );
        digest.update( signedData, 0, signedData.length );
        
        return verifier.verifySignature( token.getSignature() );
    }
    
    private static X509Certificate findCertificate( Collection<X509Certificate> trustedCertificates, IssuerSerial signer )
    {
        final BigInteger serialNumber = signer.getSerial().getValue();
        final X500Principal issuer = new X500Principal( signer.getIssuer().getNames()[0].getName().toString() );
        X509Certificate signerCertificate = (X509Certificate) CollectionUtils.find( trustedCertificates, new Predicate()
        {
            @Override
            public boolean evaluate( Object object )
            {
                X509Certificate cert = (X509Certificate) object;
                
                boolean serialMatches = cert.getSerialNumber().equals( serialNumber );
                boolean issuerEquals = dnMatches( issuer, cert.getIssuerX500Principal() );
                
                return serialMatches && issuerEquals;
            }
        } );
        return signerCertificate;
    }
    
    private static boolean dnMatches( X500Principal p1, X500Principal p2 )
    {
        try
        {
            List<Rdn> rdn1 = new LdapName( p1.getName() ).getRdns();
            List<Rdn> rdn2 = new LdapName( p2.getName() ).getRdns();
            
            if ( rdn1.size() != rdn2.size() )
                return false;
            
            return rdn1.containsAll( rdn2 );
        }
        catch ( InvalidNameException e )
        {
            throw new RuntimeException( e );
        }
    }
    
    private IssuerSerial issuerSerial()
    {
        if ( issuerSerial == null )
        {
            synchronized ( this )
            {
                if ( issuerSerial == null )
                {
                    issuerSerial = buildIssuerSerial();
                }
            }
        }
        return issuerSerial;
    }
    
    private CipherParameters parameters()
    {
        if ( parameters == null )
        {
            synchronized ( this )
            {
                if ( parameters == null )
                {
                    if ( rng != null )
                    {
                        parameters = new ParametersWithRandom( parameters, rng );
                    }
                    else
                    {
                        parameters = buildRsaParameters();
                    }
                }
            }
        }
        return parameters;
    }
    
    private IssuerSerial buildIssuerSerial()
    {
        X500Name issuer = X500Name.getInstance( certificate.getIssuerX500Principal().getEncoded() );
        
        IssuerSerial issuerSerial = new IssuerSerial( new GeneralNames( new GeneralName( issuer ) ), new DERInteger(
                certificate.getSerialNumber() ) );
        return issuerSerial;
    }
    
    private RSAKeyParameters buildRsaParameters()
    {
        if ( privateKey instanceof RSAPrivateCrtKey )
        {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) privateKey;
            
            return new RSAPrivateCrtKeyParameters( k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getPrimeP(),
                    k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient() );
        }
        else
        {
            return new RSAKeyParameters( true, privateKey.getModulus(), privateKey.getPrivateExponent() );
        }
    }
}
