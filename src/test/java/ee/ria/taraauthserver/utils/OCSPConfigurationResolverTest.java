package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.EidasAuthConfiguration;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static ee.ria.taraauthserver.config.AuthConfigurationProperties.*;
import static ee.ria.taraauthserver.config.AuthConfigurationProperties.Ocsp.*;
import static org.junit.Assert.*;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = EidasAuthConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class
)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class OCSPConfigurationResolverTest extends BaseTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

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

    @Mock
    private IdCardAuthConfigurationProperties idCardConfigurationProvider;

    @Test
    public void resolveShouldFailWhenNoUserCertProvided() {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("User certificate is missing!");

        new OCSPConfigurationResolver(idCardConfigurationProvider).resolve(null);
    }

    @Test
    public void resolveShouldFailWithNoExplicitlyDefinedConfigurationAndNoAiaOcspExtension() {
        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("OCSP configuration invalid! This user certificate's issuer, " +
                "issued by 'TEST of ESTEID-SK 2011', has no explicitly configured OCSP " +
                "nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration");

        new OCSPConfigurationResolver(idCardConfigurationProvider).resolve(mockUserCertificate2011);
    }

    @Test
    public void resolveShouldSucceedWithEsteid2018CertWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        assertEquals(1, conf.size());
        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals(false, conf.get(0).isNonceDisabled());
        assertEquals(null, conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithEsteid2015CertWithAiaExtensionAndWithoutExplicitConfiguration() {

        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2015);

        assertEquals(1, conf.size());
        assertEquals("http://aia.demo.sk.ee/esteid2015", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID-SK 2015"), conf.get(0).getIssuerCn());
        assertEquals(false, conf.get(0).isNonceDisabled());
        assertEquals(null, conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedithEsteid2015CertWithoutAiaExtensionAndWithExplicitConfiguration() {

        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList(getMockOcspConfiguration(
                Arrays.asList("TEST of ESTEID-SK 2015", "ESTEID-SK 2015"),
                "http://localhost:1234/ocsp",
                true, 3, 901, 1111, 2222,
                "Responder.pem")));

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockIDCardUserCertificate2015withoutAiaExtension);

        assertEquals(1, conf.size());
        assertEquals("http://localhost:1234/ocsp", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID-SK 2015", "ESTEID-SK 2015"), conf.get(0).getIssuerCn());
        assertEquals(true, conf.get(0).isNonceDisabled());
        assertEquals("Responder.pem", conf.get(0).getResponderCertificateCn());
        assertEquals(3, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldFailWithEsteid2015CertWithoutAiaExtensionAndWithoutExplicitConfiguration() {
        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList());

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("OCSP configuration invalid! This user certificate's issuer, issued by 'TEST of ESTEID-SK 2015', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain the OCSP url in the AIA extension! Please check your configuration");

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockIDCardUserCertificate2015withoutAiaExtension);
    }

    @Test
    public void resolveShouldSucceedWithEsteid2018CertAndExplicitlyDefinedConfiguration() {
        Mockito.when(idCardConfigurationProvider.getOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        true, 3, 901, 1111, 2222,
                        "Responder.pem")
        ));

        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        assertEquals(1, conf.size());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals("http://localhost:1234/ocsp", conf.get(0).getUrl());
        assertEquals(true, conf.get(0).isNonceDisabled());
        assertEquals("Responder.pem", conf.get(0).getResponderCertificateCn());
        assertEquals(3, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(0).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithASingleFallbackOcsp() {
        Mockito.when(idCardConfigurationProvider.getFallbackOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem")
        ));


        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        assertEquals(2, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals(false, conf.get(0).isNonceDisabled());
        assertEquals(null, conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp", conf.get(1).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID-SK 2011", "TEST of ESTEID-SK 2015", "TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertEquals(false, conf.get(1).isNonceDisabled());
        assertEquals("TEST_of_SK_OCSP_RESPONDER_2011.pem", conf.get(1).getResponderCertificateCn());
        assertEquals(3, conf.get(1).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(1).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(1).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(1).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithMultipleFallbackOcspsAndSelectSingleRelevantConf() {
        Mockito.when(idCardConfigurationProvider.getFallbackOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID-SK 2011"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem"),
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID-SK 2015"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem"),
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp",
                        false, 3, 901, 1111, 2222,
                        "TEST_of_SK_OCSP_RESPONDER_2011.pem")
        ));


        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        assertEquals(2, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals(false, conf.get(0).isNonceDisabled());
        assertEquals(null, conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp", conf.get(1).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertEquals(false, conf.get(1).isNonceDisabled());
        assertEquals("TEST_of_SK_OCSP_RESPONDER_2011.pem", conf.get(1).getResponderCertificateCn());
        assertEquals(3, conf.get(1).getAcceptedClockSkewInSeconds());
        assertEquals(901, conf.get(1).getResponseLifetimeInSeconds());
        assertEquals(1111, conf.get(1).getConnectTimeoutInMilliseconds());
        assertEquals(2222, conf.get(1).getReadTimeoutInMilliseconds());
    }

    @Test
    public void resolveShouldSucceedWithMultipleFallbackOcspsAndSelectMultipleRelevantConfs() {
        Mockito.when(idCardConfigurationProvider.getFallbackOcsp()).thenReturn(Arrays.asList(
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp1",
                        false, 3, 901, 1111, 2222,
                        "TEST_RESPONDER1.pem"),
                getMockOcspConfiguration(
                        Arrays.asList("TEST of ESTEID2018"),
                        "http://localhost:1234/ocsp2",
                        true, 3, 901, 1111, 2222,
                        "TEST_RESPONDER2.pem")
        ));


        List<Ocsp> conf = new OCSPConfigurationResolver(idCardConfigurationProvider)
                .resolve(mockUserCertificate2018);

        assertEquals(3, conf.size());

        assertEquals("http://aia.demo.sk.ee/esteid2018", conf.get(0).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(0).getIssuerCn());
        assertEquals(false, conf.get(0).isNonceDisabled());
        assertEquals(null, conf.get(0).getResponderCertificateCn());
        assertEquals(DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS, conf.get(0).getAcceptedClockSkewInSeconds());
        assertEquals(DEFAULT_RESPONSE_LIFETIME_IN_SECONDS, conf.get(0).getResponseLifetimeInSeconds());
        assertEquals(DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS, conf.get(0).getConnectTimeoutInMilliseconds());
        assertEquals(DEFAULT_READ_TIMEOUT_IN_MILLISECONDS, conf.get(0).getReadTimeoutInMilliseconds());

        assertEquals("http://localhost:1234/ocsp1", conf.get(1).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(1).getIssuerCn());
        assertEquals(false, conf.get(1).isNonceDisabled());
        assertEquals("TEST_RESPONDER1.pem", conf.get(1).getResponderCertificateCn());

        assertEquals("http://localhost:1234/ocsp2", conf.get(2).getUrl());
        assertEquals(Arrays.asList("TEST of ESTEID2018"), conf.get(2).getIssuerCn());
        assertEquals(true, conf.get(2).isNonceDisabled());
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
