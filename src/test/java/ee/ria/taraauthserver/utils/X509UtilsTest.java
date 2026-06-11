package ee.ria.taraauthserver.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class X509UtilsTest {

    @Test
    void getCertificatePolicyOids_WhenCertificateHasCertificatePolicies_ReturnsPolicyOids() {
        X509Certificate certificate = TestUtils.loadCertificateFromResource("id-card/38001085718(TEST_of_ESTEID2018).cer.pem");

        List<ASN1ObjectIdentifier> result = X509Utils.getCertificatePolicyOids(certificate);

        assertEquals(List.of(
                new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1"),
                new ASN1ObjectIdentifier("0.4.0.2042.1.2")
        ), result);
    }

    @Test
    void getCertificatePolicyOids_WhenCertificateHasNoCertificatePolicies_ReturnsEmptyList() throws Exception {
        X509Certificate certificate = generateCertificateWithoutPolicies();

        List<ASN1ObjectIdentifier> result = X509Utils.getCertificatePolicyOids(certificate);

        assertTrue(result.isEmpty());
    }

    @Test
    void getCertificatePolicyOids_WhenCertificateCannotBeEncoded_ThrowsIllegalStateException() throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenThrow(new CertificateEncodingException("test error"));

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> X509Utils.getCertificatePolicyOids(certificate)
        );

        Assertions.assertEquals("Failed to extract certificate policy OIDs", exception.getMessage());
        assertInstanceOf(CertificateEncodingException.class, exception.getCause());
    }

    private static X509Certificate generateCertificateWithoutPolicies() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name("CN=test");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
        Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(1)));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }

}
