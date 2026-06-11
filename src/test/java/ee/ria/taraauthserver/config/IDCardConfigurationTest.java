package ee.ria.taraauthserver.config;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.CertificateChain;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.FallbackOcspServer;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.PrimaryOcspServer;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.TruststoreConfigurationProperties;
import ee.ria.taraauthserver.utils.X509Utils;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.FallbackOcspServiceConfiguration;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.validator.AuthTokenValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IDCardConfigurationTest {

    private static final String TRUSTSTORE_PATH = "file:src/test/resources/idcard-truststore-test.p12";
    private static final String TRUSTSTORE_PASSWORD = "changeit";
    private static final List<String> TRUSTSTORE_CERTIFICATE_CNS = List.of(
            "ESTEID-SK 2015",
            "ESTEID2018",
            "TEST of EE Certification Centre Root CA",
            "TEST of ESTEID-SK 2015",
            "TEST of ESTEID2018",
            "TEST of KLASS3-SK 2010");
    private static final X500Name ISSUER_DN = new X500Name("CN=Test Issuer");

    private final IDCardConfiguration configuration = new IDCardConfiguration();
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUp() {
        logAppender = new ListAppender<>();
        logAppender.start();
        ((Logger) LoggerFactory.getLogger(IDCardConfiguration.class)).addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(IDCardConfiguration.class)).detachAppender(logAppender);
    }

    @Nested
    class Keystores {

        @Test
        void issuerKeystore_whenTruststoreFileExists_loadsTruststoreWithAllCertificates() throws Exception {
            KeyStore keystore = configuration.issuerKeystore(resourceLoader, idCardProperties(ocsp()));

            assertThat(keystore.size()).isEqualTo(6);
        }

        @Test
        void ocspResponderKeystore_whenTruststoreFileExists_loadsTruststoreWithAllCertificates() throws Exception {
            KeyStore keystore = configuration.ocspResponderKeystore(resourceLoader, idCardProperties(ocsp()));

            assertThat(keystore.size()).isEqualTo(6);
        }

        @Test
        void issuerKeystore_whenTruststoreFileMissing_throwsIllegalStateException() {
            IdCardAuthConfigurationProperties properties = idCardProperties(ocsp());
            properties.getIssuerTruststore().setPath("file:src/test/resources/missing-truststore.p12");

            assertThatThrownBy(() -> configuration.issuerKeystore(resourceLoader, properties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Could not load truststore of type PKCS12 from file:src/test/resources/missing-truststore.p12!");
        }

        @Test
        void issuerKeystore_whenWrongPassword_throwsIllegalStateException() {
            IdCardAuthConfigurationProperties properties = idCardProperties(ocsp());
            properties.getIssuerTruststore().setPassword("wrong-password");

            assertThatThrownBy(() -> configuration.issuerKeystore(resourceLoader, properties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Could not load truststore of type PKCS12 from " + TRUSTSTORE_PATH + "!");
        }

        @Test
        void ocspResponderKeystore_whenResponderTruststoreFileMissing_throwsIllegalStateException() {
            IdCardAuthConfigurationProperties properties = idCardProperties(ocsp());
            properties.getOcsp().getResponderTruststore().setPath("file:src/test/resources/missing-truststore.p12");

            assertThatThrownBy(() -> configuration.ocspResponderKeystore(resourceLoader, properties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Could not load truststore of type PKCS12 from file:src/test/resources/missing-truststore.p12!");
        }
    }

    @Nested
    class TrustedCertificatesMaps {

        @Test
        void issuerTrustedCertificatesMap_whenKeystoreContainsCertificates_mapsCertificatesBySubjectCommonName() {
            Map<String, X509Certificate> result = configuration.issuerTrustedCertificatesMap(issuerKeystore());

            assertThat(result.keySet()).containsExactlyInAnyOrderElementsOf(TRUSTSTORE_CERTIFICATE_CNS);
        }

        @Test
        void issuerTrustedCertificatesMap_whenKeystoreContainsCertificates_logsEachTrustedCertificate() {
            configuration.issuerTrustedCertificatesMap(issuerKeystore());

            List<String> certificateLogs = loggedMessages().stream()
                    .filter(message -> message.startsWith("Trusted issuer certificate added to configuration - CN: "))
                    .toList();
            assertThat(certificateLogs).hasSize(6);
            assertThat(certificateLogs).anySatisfy(message ->
                    assertThat(message).startsWith("Trusted issuer certificate added to configuration - CN: ESTEID2018, serialnumber: "));
        }

        @Test
        void ocspResponderTrustedCertificatesMap_whenKeystoreContainsCertificates_mapsCertificatesBySubjectDistinguishedName() {
            Map<X500Name, X509Certificate> result = configuration.ocspResponderTrustedCertificatesMap(issuerKeystore());

            assertThat(result.keySet().stream().map(X509Utils::getFirstCNFromX500Name))
                    .containsExactlyInAnyOrderElementsOf(TRUSTSTORE_CERTIFICATE_CNS);
        }

        @Test
        void ocspResponderTrustedCertificatesMap_whenKeystoreContainsCertificates_logsEachTrustedCertificate() {
            configuration.ocspResponderTrustedCertificatesMap(issuerKeystore());

            List<String> certificateLogs = loggedMessages().stream()
                    .filter(message -> message.startsWith("Trusted OCSP responder certificate added to configuration - CN: "))
                    .toList();
            assertThat(certificateLogs).hasSize(6);
        }

        @Test
        void issuerTrustedCertificatesMap_whenKeystoreEmpty_throwsIllegalArgumentException() {
            assertThatThrownBy(() -> configuration.issuerTrustedCertificatesMap(emptyKeystore()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Failed to read trusted certificates from id-card truststore: ");
        }

        @Test
        void issuerTrustedCertificatesMap_whenDuplicateSubjectCommonName_throwsIllegalArgumentException() throws Exception {
            KeyStore keystore = keystoreWith(
                    generateCertificate("CN=Duplicate CA", false),
                    generateCertificate("CN=Duplicate CA", false));

            assertThatThrownBy(() -> configuration.issuerTrustedCertificatesMap(keystore))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Failed to read trusted certificates from id-card truststore: ");
        }

        @Test
        void ocspResponderTrustedCertificatesMap_whenKeystoreEmpty_throwsIllegalArgumentException() {
            assertThatThrownBy(() -> configuration.ocspResponderTrustedCertificatesMap(emptyKeystore()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Failed to read trusted certificates from id-card truststore: ");
        }

        @Test
        void ocspResponderTrustedCertificatesMap_whenDuplicateSubjectDistinguishedName_throwsIllegalArgumentException() throws Exception {
            KeyStore keystore = keystoreWith(
                    generateCertificate("CN=Duplicate CA", false),
                    generateCertificate("CN=Duplicate CA", false));

            assertThatThrownBy(() -> configuration.ocspResponderTrustedCertificatesMap(keystore))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Failed to read trusted certificates from id-card truststore: ");
        }
    }

    @Nested
    class DefaultAuthTokenValidator {

        @Test
        void defaultAuthTokenValidator_whenOcspDisabled_buildsValidatorWithoutRevocationCheck() throws Exception {
            Ocsp ocsp = ocsp();
            ocsp.setEnabled(false);

            AuthTokenValidator validator = buildDefaultValidator(idCardProperties(ocsp));

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains("OCSP check is disabled");
            assertThat(loggedMessages()).doesNotContain("Using ResilientOcspCertificateRevocationChecker for OCSP");
        }

        @Test
        void defaultAuthTokenValidator_whenChainHasNoFallbackServers_buildsValidatorWithoutFallbackConfigurations() throws Exception {
            Ocsp ocsp = ocsp(chain(ISSUER_DN, null, null));

            AuthTokenValidator validator = buildDefaultValidator(idCardProperties(ocsp));

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains(
                    "No fallback configurations found for issuer " + ISSUER_DN,
                    "Using ResilientOcspCertificateRevocationChecker for OCSP");
        }

        @Test
        void defaultAuthTokenValidator_whenChainHasFirstFallbackOnly_buildsFallbackConfigurationWithoutNext() throws Exception {
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer("http://fallback1.test/ocsp"), null));

            buildDefaultValidator(idCardProperties(ocsp));

            assertThat(loggedMessages()).contains(
                    "Found first fallback configuration for issuer " + ISSUER_DN,
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: null, does support nonce: true");
            assertThat(loggedMessages()).doesNotContain("Found second fallback configuration for issuer " + ISSUER_DN);
        }

        @Test
        void defaultAuthTokenValidator_whenChainHasFirstAndSecondFallback_chainsSecondAfterFirst() throws Exception {
            Ocsp ocsp = ocsp(chain(ISSUER_DN,
                    fallbackServer("http://fallback1.test/ocsp"),
                    fallbackServer("http://fallback2.test/ocsp")));

            buildDefaultValidator(idCardProperties(ocsp));

            assertThat(loggedMessages()).contains(
                    "Found first fallback configuration for issuer " + ISSUER_DN,
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: http://fallback2.test/ocsp, does support nonce: true",
                    "Found second fallback configuration for issuer " + ISSUER_DN,
                    "Created a fallback configuration. Fallback URL: http://fallback2.test/ocsp, next fallback URL: null, does support nonce: true");
        }

        @Test
        void defaultAuthTokenValidator_whenFallbackServerNonceDisabled_createsFallbackConfigurationWithoutNonceSupport() throws Exception {
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setNonceEnabled(false);
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));

            buildDefaultValidator(idCardProperties(ocsp));

            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: null, does support nonce: false");
        }

        @Test
        void defaultAuthTokenValidator_whenResponderSubjectDnConfiguredWithValidResponderCertificate_buildsValidator() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Test OCSP Responder", true);
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            AuthTokenValidator validator = configuration.defaultAuthTokenValidator(
                    authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates);

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains("Using ResilientOcspCertificateRevocationChecker for OCSP");
        }

        @Test
        void defaultAuthTokenValidator_whenResponderCertificateLacksOcspSigningExtension_throwsRuntimeException() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Not An OCSP Responder", false);
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            assertThatExceptionOfType(RuntimeException.class)
                    .isThrownBy(() -> configuration.defaultAuthTokenValidator(
                            authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates))
                    .withMessage("Error building the Web eID auth token validator.")
                    .withCauseInstanceOf(OCSPCertificateException.class);
        }

        @Test
        void defaultAuthTokenValidator_whenSecondFallbackResponderSubjectDnConfiguredWithValidResponderCertificate_buildsValidatorWithSecondFallback() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Test OCSP Responder", true);
            FallbackOcspServer secondFallbackServer = fallbackServer("http://fallback2.test/ocsp");
            secondFallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer("http://fallback1.test/ocsp"), secondFallbackServer));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            AuthTokenValidator validator = configuration.defaultAuthTokenValidator(
                    authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates);

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains(
                    "Found second fallback configuration for issuer " + ISSUER_DN,
                    "Created a fallback configuration. Fallback URL: http://fallback2.test/ocsp, next fallback URL: null, does support nonce: true");
        }

        @Test
        void defaultAuthTokenValidator_whenSecondFallbackResponderCertificateLacksOcspSigningExtension_throwsRuntimeException() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Not An OCSP Responder", false);
            FallbackOcspServer secondFallbackServer = fallbackServer("http://fallback2.test/ocsp");
            secondFallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer("http://fallback1.test/ocsp"), secondFallbackServer));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            assertThatExceptionOfType(RuntimeException.class)
                    .isThrownBy(() -> configuration.defaultAuthTokenValidator(
                            authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates))
                    .withMessage("Error building the Web eID auth token validator.")
                    .withCauseInstanceOf(OCSPCertificateException.class);
        }

        @Test
        void defaultAuthTokenValidator_whenSiteOriginIsNotValidUri_throwsRuntimeException() {
            Ocsp ocsp = ocsp(chain(ISSUER_DN, null, null));

            assertThatExceptionOfType(RuntimeException.class)
                    .isThrownBy(() -> configuration.defaultAuthTokenValidator(
                            authProperties("https://example.com/invalid uri"), idCardProperties(ocsp),
                            issuerCertificates(), Map.of()))
                    .withMessage("Error building the Web eID auth token validator.")
                    .withCauseInstanceOf(java.net.URISyntaxException.class);
        }

        @Test
        void defaultAuthTokenValidator_whenResponderSubjectDnNotInTrustedResponderMap_buildsValidatorWithoutResponderCertificate() throws Exception {
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setResponderSubjectDn(new X500Name("CN=Unknown OCSP Responder"));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));

            AuthTokenValidator validator = configuration.defaultAuthTokenValidator(
                    authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), Map.of());

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: null, does support nonce: true");
        }
    }

    @Nested
    class EidasProxyAuthTokenValidator {

        @Test
        void eidasProxyAuthTokenValidator_whenBothFallbackServersEnabledForEidasProxy_chainsSecondAfterFirst() throws Exception {
            Ocsp ocsp = ocsp(chain(ISSUER_DN,
                    fallbackServer("http://fallback1.test/ocsp"),
                    fallbackServer("http://fallback2.test/ocsp")));

            AuthTokenValidator validator = buildEidasProxyValidator(idCardProperties(ocsp));

            assertThat(validator).isNotNull();
            assertThat(loggedMessages().stream()
                    .filter(message -> message.equals("Found eIDAS proxy fallback configuration for issuer " + ISSUER_DN)))
                    .hasSize(2);
            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: http://fallback2.test/ocsp, does support nonce: true",
                    "Created a fallback configuration. Fallback URL: http://fallback2.test/ocsp, next fallback URL: null, does support nonce: true");
        }

        @Test
        void eidasProxyAuthTokenValidator_whenFirstFallbackDisabledForEidasProxy_usesOnlySecondFallback() throws Exception {
            FallbackOcspServer firstFallback = fallbackServer("http://fallback1.test/ocsp");
            firstFallback.setEnabledForEidasProxy(false);
            Ocsp ocsp = ocsp(chain(ISSUER_DN, firstFallback, fallbackServer("http://fallback2.test/ocsp")));

            buildEidasProxyValidator(idCardProperties(ocsp));

            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback2.test/ocsp, next fallback URL: null, does support nonce: true");
            assertThat(loggedMessages()).noneSatisfy(message ->
                    assertThat(message).contains("Fallback URL: http://fallback1.test/ocsp"));
        }

        @Test
        void eidasProxyAuthTokenValidator_whenSecondFallbackDisabledForEidasProxy_usesOnlyFirstFallback() throws Exception {
            FallbackOcspServer secondFallback = fallbackServer("http://fallback2.test/ocsp");
            secondFallback.setEnabledForEidasProxy(false);
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer("http://fallback1.test/ocsp"), secondFallback));

            buildEidasProxyValidator(idCardProperties(ocsp));

            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: null, does support nonce: true");
            assertThat(loggedMessages()).noneSatisfy(message ->
                    assertThat(message).contains("Fallback URL: http://fallback2.test/ocsp"));
        }

        @Test
        void eidasProxyAuthTokenValidator_whenNoFallbackServersEnabledForEidasProxy_buildsValidatorWithoutFallbackConfigurations() throws Exception {
            FallbackOcspServer disabledFallback = fallbackServer("http://fallback1.test/ocsp");
            disabledFallback.setEnabledForEidasProxy(false);
            Ocsp ocsp = ocsp(
                    chain(ISSUER_DN, disabledFallback, null),
                    chain(new X500Name("CN=Issuer Without Fallbacks"), null, null));

            AuthTokenValidator validator = buildEidasProxyValidator(idCardProperties(ocsp));

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).noneSatisfy(message ->
                    assertThat(message).startsWith("Found eIDAS proxy fallback configuration"));
            assertThat(loggedMessages()).contains("Using ResilientOcspCertificateRevocationChecker for OCSP");
        }

        @Test
        void eidasProxyAuthTokenValidator_whenResponderSubjectDnConfiguredWithValidResponderCertificate_buildsValidator() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Test OCSP Responder", true);
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            AuthTokenValidator validator = configuration.eidasProxyAuthTokenValidator(
                    authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates);

            assertThat(validator).isNotNull();
            assertThat(loggedMessages()).contains(
                    "Found eIDAS proxy fallback configuration for issuer " + ISSUER_DN,
                    "Using ResilientOcspCertificateRevocationChecker for OCSP");
        }

        @Test
        void eidasProxyAuthTokenValidator_whenResponderCertificateLacksOcspSigningExtension_throwsRuntimeException() throws Exception {
            X509Certificate responderCertificate = generateCertificate("CN=Not An OCSP Responder", false);
            FallbackOcspServer fallbackServer = fallbackServer("http://fallback1.test/ocsp");
            fallbackServer.setResponderSubjectDn(X509Utils.getSubjectDN(responderCertificate));
            Ocsp ocsp = ocsp(chain(ISSUER_DN, fallbackServer, null));
            Map<X500Name, X509Certificate> responderCertificates
                    = Map.of(X509Utils.getSubjectDN(responderCertificate), responderCertificate);

            assertThatExceptionOfType(RuntimeException.class)
                    .isThrownBy(() -> configuration.eidasProxyAuthTokenValidator(
                            authProperties("https://example.com"), idCardProperties(ocsp), issuerCertificates(), responderCertificates))
                    .withMessage("Error building the Web eID auth token validator.")
                    .withCauseInstanceOf(OCSPCertificateException.class);
        }
    }

    @Nested
    class AiaOcspConfiguration {

        @Test
        void getAiaOcspServiceConfiguration_whenChainHasNonceDisabledPrimaryServer_collectsIssuerDnAsNonceDisabled() throws Exception {
            X500Name nonceDisabledIssuerDn = new X500Name("CN=Nonce Disabled Issuer");
            CertificateChain nonceDisabledChain = chain(nonceDisabledIssuerDn, null, null);
            nonceDisabledChain.getPrimaryServer().setNonceEnabled(false);
            Ocsp ocsp = ocsp(chain(ISSUER_DN, null, null), nonceDisabledChain);

            Map<String, X509Certificate> issuerCertificates = issuerCertificates();
            Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(issuerCertificates.values());
            CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(issuerCertificates.values());

            AiaOcspServiceConfiguration result = IDCardConfiguration.getAiaOcspServiceConfiguration(ocsp, trustAnchors, certStore);

            assertThat(result.getNonceDisabledIssuerDNs()).containsExactly(nonceDisabledIssuerDn);
        }

        @Test
        void getAiaOcspServiceConfiguration_whenAllPrimaryServersNonceEnabled_collectsNoNonceDisabledIssuerDns() throws Exception {
            Ocsp ocsp = ocsp(chain(ISSUER_DN, null, null));

            Map<String, X509Certificate> issuerCertificates = issuerCertificates();
            Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(issuerCertificates.values());
            CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(issuerCertificates.values());

            AiaOcspServiceConfiguration result = IDCardConfiguration.getAiaOcspServiceConfiguration(ocsp, trustAnchors, certStore);

            assertThat(result.getNonceDisabledIssuerDNs()).isEmpty();
        }
    }

    @Nested
    class FallbackOcspServiceConfigurationLogging {

        @Test
        void logFallbackOcspServiceConfiguration_whenNextFallbackConfigurationHasNullAccessLocation_logsNullNextFallbackUrl() {
            FallbackOcspServiceConfiguration nextFallbackConfiguration = mock(FallbackOcspServiceConfiguration.class);
            when(nextFallbackConfiguration.getAccessLocation()).thenReturn(null);

            FallbackOcspServiceConfiguration fallbackConfiguration = mock(FallbackOcspServiceConfiguration.class);
            when(fallbackConfiguration.getAccessLocation()).thenReturn(URI.create("http://fallback1.test/ocsp"));
            when(fallbackConfiguration.getNextFallbackConfiguration()).thenReturn(nextFallbackConfiguration);
            when(fallbackConfiguration.doesSupportNonce()).thenReturn(true);

            IDCardConfiguration.logFallbackOcspServiceConfiguration(fallbackConfiguration);

            assertThat(loggedMessages()).contains(
                    "Created a fallback configuration. Fallback URL: http://fallback1.test/ocsp, next fallback URL: null, does support nonce: true");
        }
    }

    private AuthTokenValidator buildDefaultValidator(IdCardAuthConfigurationProperties idCardProperties) throws Exception {
        return configuration.defaultAuthTokenValidator(
                authProperties("https://example.com"), idCardProperties, issuerCertificates(), responderCertificates());
    }

    private AuthTokenValidator buildEidasProxyValidator(IdCardAuthConfigurationProperties idCardProperties) throws Exception {
        return configuration.eidasProxyAuthTokenValidator(
                authProperties("https://example.com"), idCardProperties, issuerCertificates(), responderCertificates());
    }

    private Map<String, X509Certificate> issuerCertificates() throws Exception {
        return configuration.issuerTrustedCertificatesMap(issuerKeystore());
    }

    private Map<X500Name, X509Certificate> responderCertificates() throws Exception {
        return configuration.ocspResponderTrustedCertificatesMap(issuerKeystore());
    }

    private KeyStore issuerKeystore() {
        return configuration.issuerKeystore(resourceLoader, idCardProperties(ocsp()));
    }

    private List<String> loggedMessages() {
        return logAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private static AuthConfigurationProperties authProperties(String siteOrigin) throws Exception {
        AuthConfigurationProperties properties = new AuthConfigurationProperties();
        properties.setSiteOrigin(new URL(siteOrigin));
        return properties;
    }

    private static IdCardAuthConfigurationProperties idCardProperties(Ocsp ocsp) {
        IdCardAuthConfigurationProperties properties = new IdCardAuthConfigurationProperties();
        properties.setIssuerTruststore(truststore());
        properties.setOcsp(ocsp);
        return properties;
    }

    private static TruststoreConfigurationProperties truststore() {
        TruststoreConfigurationProperties truststore = new TruststoreConfigurationProperties();
        truststore.setPath(TRUSTSTORE_PATH);
        truststore.setType("PKCS12");
        truststore.setPassword(TRUSTSTORE_PASSWORD);
        return truststore;
    }

    private static Ocsp ocsp(CertificateChain... certificateChains) {
        Ocsp ocsp = new Ocsp();
        ocsp.setResponderTruststore(truststore());
        ocsp.setCertificateChains(List.of(certificateChains));
        return ocsp;
    }

    private static CertificateChain chain(X500Name issuerDn, FallbackOcspServer firstFallbackServer, FallbackOcspServer secondFallbackServer) {
        CertificateChain chain = new CertificateChain();
        chain.setIssuerDn(issuerDn);
        chain.setPrimaryServer(new PrimaryOcspServer());
        chain.setFirstFallbackServer(firstFallbackServer);
        chain.setSecondFallbackServer(secondFallbackServer);
        return chain;
    }

    private static FallbackOcspServer fallbackServer(String url) {
        FallbackOcspServer fallbackServer = new FallbackOcspServer();
        fallbackServer.setUrl(url);
        return fallbackServer;
    }

    private static KeyStore emptyKeystore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);
        return keystore;
    }

    private static KeyStore keystoreWith(X509Certificate... certificates) throws Exception {
        KeyStore keystore = emptyKeystore();
        for (int i = 0; i < certificates.length; i++) {
            keystore.setCertificateEntry("alias-" + i, certificates[i]);
        }
        return keystore;
    }

    private static X509Certificate generateCertificate(String subjectDn, boolean withOcspSigningExtension) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X500Name subject = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(Duration.ofDays(1))),
                Date.from(Instant.now().plus(Duration.ofDays(1))),
                subject,
                keyPair.getPublic());
        if (withOcspSigningExtension) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
