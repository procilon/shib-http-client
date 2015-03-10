package de.tudarmstadt.ukp.shibhttpclient.authentication.sv;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;

public class SignatureTest
{
    private static Date NOW = new Date();
    
    /**
     * this is more of a system-test.
     */
    @Test
    public void roundTrip() throws Exception
    {
        KeyPair keyPair = generateKeys();
        X509Certificate certificate = signCertificate( keyPair );
        
        roundTrip( (RSAPrivateKey) keyPair.getPrivate(), certificate );
    }
    
    private void roundTrip( RSAPrivateKey privateKey, X509Certificate certificate ) throws Exception
    {
        String userName = "test-user";
        String roleName = "test-role";
        
        TokenData tbsToken = new TokenData( userName, Collections.singleton( new Role( roleName ) ), NOW, new Date( NOW.getTime() + 60000 ) );
        
        TokenSigner signer = new TokenSigner( privateKey, certificate );
        
        SignedToken signedToken = signer.sign( tbsToken );
        byte[] encodedToken = signedToken.getDERObject().getDEREncoded();
        
        System.out.println( DatatypeConverter.printBase64Binary( encodedToken ) );
        
        SignedToken parsedToken = SignedToken.parse( ASN1Sequence.getInstance( encodedToken ) );
        
        boolean verified = TokenSigner.verify( parsedToken, Collections.singleton( certificate ) );
        if ( !verified )
        {
            throw new IllegalStateException( "SignatureVerification failed" );
        }
        
        assertThat( parsedToken.getData().getId(), is( userName ) );
        Set<Role> roles = parsedToken.getData().getRoles();
        assertThat( roles.iterator().next().getName(), is( roleName ) );
    }
    
    private static X509Certificate signCertificate( KeyPair keyPair ) throws Exception
    {
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo( ASN1Sequence.getInstance( keyPair.getPublic().getEncoded() ) );
        
        X500Name subject = new X500Name( "cn=test" );
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder( subject, BigInteger.ONE, NOW, new Date(
                NOW.getTime() + 60000 ), subject, publicKeyInfo );
        
        X509CertificateHolder certificateHolder = certificateBuilder.build( new JcaContentSignerBuilder( "SHA256WithRSA" ).build( keyPair
                .getPrivate() ) );
        
        return new X509CertificateObject( X509CertificateStructure.getInstance( certificateHolder.toASN1Structure() ) );
    }
    
    private static KeyPair generateKeys() throws NoSuchAlgorithmException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance( "RSA" );
        
        generator.initialize( 1024 );
        
        return generator.generateKeyPair();
    }
}
