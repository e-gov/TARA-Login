package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.utils.TestIDCardConfiguration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp.*;
import static java.util.List.of;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {TestIDCardConfiguration.class})
@ActiveProfiles({"mock_configuration"})
public class OCSPConfigurationResolverTest {

    @Autowired
    @Qualifier("mockIDCardUserCertificate2015")
    private X509Certificate mockUserCertificate2015;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2011")
    private X509Certificate mockUserCertificate2011;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2015withoutAiaExtension")
    private X509Certificate mockIDCardUserCertificate2015withoutAiaExtension;

    @Autowired
    @Qualifier("mockIDCardUserCertificate2018")
    private X509Certificate mockUserCertificate2018;

    @MockBean
    private IdCardAuthConfigurationProperties idCardConfigurationProperties;

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldFailWhenNoUserCertProvided() {
        assertNotNull(idCardConfigurationProperties);
        Exception expectedEx = assertThrows(IllegalArgumentException.class, () -> {
            new OCSPConfigurationResolver(idCardConfigurationProperties).resolve(null);
        });
        assertEquals("User certificate is missing!", expectedEx.getMessage());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldFailWithNoExplicitlyDefinedConfigurationAndNoAiaOcspExtension() {
        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of());
        Exception expectedEx = assertThrows(IllegalArgumentException.class, () -> {
            new OCSPConfigurationResolver(idCardConfigurationProperties).resolve(mockUserCertificate2011);
        });
        assertEquals("OCSP configuration invalid! This user certificate's issuer, " +
                "issued by 'TEST of ESTEID-SK 2011', has no explicitly configured OCSP " +
                "nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration", expectedEx.getMessage());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldSucceedWithEsteid2018CertWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of());

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2018);

        assertEquals(1, conf.size());
        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertFalse(conf.get(0).isNonceDisabled());
        assertNull(conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldSucceedWithEsteid2015CertWithAiaExtensionAndWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of());

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2015);

        assertEquals(1, conf.size());
        assertEquals("http://aia.demo.sk.ee/esteid2015", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID-SK 2015"), conf.get(0).getIssuerCn());
        assertFalse(conf.get(0).isNonceDisabled());
        assertNull(conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldSucceedithEsteid2015CertWithoutAiaExtensionAndWithExplicitConfiguration() {

        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of(getMockOcspConfiguration(
                of("TEST of ESTEID-SK 2015", "ESTEID-SK 2015"),
                "http://localhost:1234/ocsp",
                true, 3, 901, 1111, 2222,
                "Responder.pem")));

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockIDCardUserCertificate2015withoutAiaExtension);

        assertEquals(1, conf.size());
        assertEquals("http://localhost:1234/ocsp", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID-SK 2015", "ESTEID-SK 2015"), conf.get(0).getIssuerCn());
        assertTrue(conf.get(0).isNonceDisabled());
        assertEquals("Responder.pem", conf.get(0).getResponderCertificateCn());
        assertEquals(3, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldFailWithEsteid2015CertWithoutAiaExtensionAndWithoutExplicitConfiguration() {
        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of());
        Exception expectedEx = assertThrows(IllegalArgumentException.class, () -> {
            new OCSPConfigurationResolver(idCardConfigurationProperties)
                    .resolve(mockIDCardUserCertificate2015withoutAiaExtension);
        });
        assertEquals("OCSP configuration invalid! This user certificate's issuer, issued by 'TEST of ESTEID-SK 2015', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain the OCSP url in the AIA extension! Please check your configuration", expectedEx.getMessage());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_CA_WHITELIST")
    public void resolveShouldSucceedWithEsteid2018CertAndExplicitlyDefinedConfiguration() {
        Mockito.when(idCardConfigurationProperties.getOcsp()).thenReturn(of(
                getMockOcspConfiguration(
                        of("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        true, 3, 901, 1111, 2222,
                        "Responder.pem")
        ));

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2018);

        assertEquals(1, conf.size());
        assertEquals(of("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals("http://localhost:1234/ocsp", conf.get(0).getUrl());
        assertTrue(conf.get(0).isNonceDisabled());
        assertEquals("Responder.pem", conf.get(0).getResponderCertificateCn());
        assertEquals(3, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_FAILOVER_CONF")
    public void resolveShouldSucceedWithASingleFallbackOcsp() {
        Mockito.when(idCardConfigurationProperties.getFallbackOcsp()).thenReturn(of(
                getMockOcspConfiguration(
                        of("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem")
        ));

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2018);

        assertEquals(2, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertFalse(conf.get(0).isNonceDisabled());
        assertNull(conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp", conf.get(1).getUrl());
        assertEquals(of("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertFalse(conf.get(1).isNonceDisabled());
        assertEquals("TEST_of_SK_OCSP_RESPONDER_2011.pem", conf.get(1).getResponderCertificateCn());
        assertEquals(3, conf.get(1).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(1).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(1).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(1).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_FAILOVER_CONF")
    public void resolveShouldSucceedWithMultipleFallbackOcspsAndSelectSingleRelevantConf() {
        Mockito.when(idCardConfigurationProperties.getFallbackOcsp()).thenReturn(of(
                getMockOcspConfiguration(
                        of("TEST of ESTEID-SK 2011"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem"),
                getMockOcspConfiguration(
                        of("TEST of ESTEID-SK 2015"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem"),
                getMockOcspConfiguration(
                        of("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem")
        ));


        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2018);

        assertEquals(2, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertFalse(conf.get(0).isNonceDisabled());
        assertNull(conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp", conf.get(1).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertFalse(conf.get(1).isNonceDisabled());
        assertEquals("TEST_of_SK_OCSP_RESPONDER_2011.pem", conf.get(1).getResponderCertificateCn());
        assertEquals(3, conf.get(1).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(1).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(1).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(1).getReadTimeoutInMilliseconds());
    }

    @Test
    @Tag(value = "OCSP_URL_CONF")
    @Tag(value = "OCSP_FAILOVER_CONF")
    public void resolveShouldSucceedWithMultipleFallbackOcspsAndSelectMultipleRelevantConfs() {
        Mockito.when(idCardConfigurationProperties.getFallbackOcsp()).thenReturn(of(
                getMockOcspConfiguration(
                        of("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp1",
                        false, 3, 901, 1111, 2222,
                        "TEST_RESPONDER1.pem"),
                getMockOcspConfiguration(
                        of("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp2",
                        true, 3, 901, 1111, 2222,
                        "TEST_RESPONDER2.pem")
        ));


        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProperties)
                .resolve(mockUserCertificate2018);

        assertEquals(3, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertFalse(conf.get(0).isNonceDisabled());
        assertNull(conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp1", conf.get(1).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertFalse(conf.get(1).isNonceDisabled());
        assertEquals("TEST_RESPONDER1.pem", conf.get(1).getResponderCertificateCn());

        assertEquals("http://localhost:1234/ocsp2", conf.get(2).getUrl());
        assertEquals(of("TEST of ESTEID2018"), conf.get(2).getIssuerCn());
        assertTrue(conf.get(2).isNonceDisabled());
        assertEquals("TEST_RESPONDER2.pem", conf.get(2).getResponderCertificateCn());
    }


    private Ocsp getMockOcspConfiguration(List<String> issuerCn, String url, boolean nonceDisabled, int acceptedClockSkewInSeconds, int responseLifetimeInSeconds, int connectTimeoutInMilliseconds, int readTimeoutInMilliseconds, String responderCertificate) {
        Ocsp ocspConfiguration = new Ocsp();
        ocspConfiguration.setIssuerCn(issuerCn);
        ocspConfiguration.setUrl(url);
        ocspConfiguration.setNonceDisabled(nonceDisabled);
        ocspConfiguration.setAcceptedClockSkewInSeconds(acceptedClockSkewInSeconds);
        ocspConfiguration.setResponseLifetimeInSeconds(responseLifetimeInSeconds);
        ocspConfiguration.setConnectTimeoutInMilliseconds(connectTimeoutInMilliseconds);
        ocspConfiguration.setReadTimeoutInMilliseconds(readTimeoutInMilliseconds);
        ocspConfiguration.setResponderCertificateCn(responderCertificate);
        return ocspConfiguration;
    }
}
