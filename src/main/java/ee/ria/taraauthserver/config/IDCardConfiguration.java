package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.utils.X509Utils;
import eu.webeid.ocsp.client.OcspClient;
import eu.webeid.ocsp.client.OcspClientImpl;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.FallbackOcspServiceConfiguration;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.RetryConfig;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static java.util.stream.Collectors.toMap;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@Configuration
public class IDCardConfiguration {

    private static final long CHALLENGE_NONCE_TTL_MINUTES = 5;

    private enum ValidatorType {
        DEFAULT,
        EIDAS_PROXY
    }

    @Bean
    KeyStore issuerKeystore(ResourceLoader resourceLoader, IdCardAuthConfigurationProperties configurationProvider) {
        return buildKeystore(resourceLoader, configurationProvider.getIssuerTruststore());
    }

    @Bean
    KeyStore ocspResponderKeystore(ResourceLoader resourceLoader, IdCardAuthConfigurationProperties configurationProvider) {
        return buildKeystore(resourceLoader, configurationProvider.getOcsp().getResponderTruststore());
    }

    @Bean
    public Map<String, X509Certificate> issuerTrustedCertificatesMap(KeyStore issuerKeystore) {
        Map<String, X509Certificate> trustedCertificates = buildIssuerTrustedCertificatesMap(issuerKeystore);
        logIssuerTrustedCertificatesMap(trustedCertificates);
        return trustedCertificates;
    }

    @Bean
    public Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap(KeyStore ocspResponderKeystore) {
        Map<X500Name, X509Certificate> trustedCertificates = buildOcspResponderTrustedCertificatesMap(ocspResponderKeystore);
        logOcspResponderTrustedCertificatesMap(trustedCertificates);
        return trustedCertificates;
    }

    @Bean
    public ChallengeNonceGenerator generator(ChallengeNonceStore challengeNonceStore) {
        return new ChallengeNonceGeneratorBuilder()
                .withNonceTtl(Duration.ofMinutes(CHALLENGE_NONCE_TTL_MINUTES))
                .withChallengeNonceStore(challengeNonceStore)
                .build();
    }

    @Bean
    public AuthTokenValidator defaultAuthTokenValidator(AuthConfigurationProperties authConfigurationProperties,
                                        IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                        Map<String, X509Certificate> issuerTrustedCertificatesMap,
                                        Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap) {
        return buildValidator(
                authConfigurationProperties,
                idCardAuthConfigurationProperties,
                issuerTrustedCertificatesMap,
                ocspResponderTrustedCertificatesMap,
                ValidatorType.DEFAULT
        );
    }

    @Bean
    public AuthTokenValidator eidasProxyAuthTokenValidator(AuthConfigurationProperties authConfigurationProperties,
                                                  IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                  Map<String, X509Certificate> issuerTrustedCertificatesMap,
                                                  Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap) {
        return buildValidator(
                authConfigurationProperties,
                idCardAuthConfigurationProperties,
                issuerTrustedCertificatesMap,
                ocspResponderTrustedCertificatesMap,
                ValidatorType.EIDAS_PROXY
        );
    }

    private static AuthTokenValidator buildValidator(AuthConfigurationProperties authConfigurationProperties,
                                                     IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                     Map<String, X509Certificate> issuerTrustedCertificatesMap,
                                                     Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap,
                                                     ValidatorType validatorType) {
        X509Certificate[] issuerCertificates = issuerTrustedCertificatesMap.values().toArray(new X509Certificate[0]);

        try {
            AuthTokenValidatorBuilder validatorBuilder = new AuthTokenValidatorBuilder()
                    .withSiteOrigin(authConfigurationProperties.getSiteOrigin().toURI())
                    .withTrustedCertificateAuthorities(issuerCertificates);

            AuthConfigurationProperties.Ocsp ocsp = idCardAuthConfigurationProperties.getOcsp();

            if (!ocsp.isEnabled()) {
                log.info("OCSP check is disabled");
                return validatorBuilder
                        .withoutUserCertificateRevocationCheck()
                        .build();
            }

            Set<TrustAnchor> trustedCACertificateAnchors = CertificateValidator
                    .buildTrustAnchorsFromCertificates(issuerTrustedCertificatesMap.values());
            CertStore trustedCACertificateCertStore = CertificateValidator
                    .buildCertStoreFromCertificates(issuerTrustedCertificatesMap.values());

            AiaOcspServiceConfiguration aiaOcspServiceConfiguration
                    = getAiaOcspServiceConfiguration(ocsp, trustedCACertificateAnchors, trustedCACertificateCertStore);

            List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations =
                    getFallbackOcspServiceConfigurations(
                            idCardAuthConfigurationProperties,
                            trustedCACertificateAnchors,
                            trustedCACertificateCertStore,
                            ocspResponderTrustedCertificatesMap,
                            validatorType
                    );

            OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
                    null,
                    aiaOcspServiceConfiguration,
                    fallbackOcspServiceConfigurations
            );

            OcspClient ocspClient = OcspClientImpl.build(ocsp.getRequestTimeout());

            AuthConfigurationProperties.OcspCircuitBreakerConfig ocspCircuitBreakerConfig = ocsp.getCircuitBreaker();
            CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
                    .slidingWindowType(ocspCircuitBreakerConfig.getSlidingWindowType())
                    .slidingWindowSize(ocspCircuitBreakerConfig.getSlidingWindowSize())
                    .minimumNumberOfCalls(ocspCircuitBreakerConfig.getMinimumNumberOfCalls())
                    .failureRateThreshold(ocspCircuitBreakerConfig.getFailureRateThreshold())
                    .permittedNumberOfCallsInHalfOpenState(ocspCircuitBreakerConfig.getPermittedNumberOfCallsInHalfOpenState())
                    .waitDurationInOpenState(ocspCircuitBreakerConfig.getWaitDurationInOpenState())
                    .build();

            AuthConfigurationProperties.OcspRetryConfig ocspRetryConfig = ocsp.getRetry();
            RetryConfig retryConfig = RetryConfig.custom()
                    .waitDuration(ocspRetryConfig.getWaitDuration())
                    .maxAttempts(ocspRetryConfig.getMaxAttempts())
                    .build();

            ResilientOcspCertificateRevocationChecker ocspRevocationChecker = new ResilientOcspCertificateRevocationChecker(
                    ocspClient,
                    ocspServiceProvider,
                    circuitBreakerConfig,
                    retryConfig,
                    ocsp.getAllowedResponseTimeSkew(),
                    ocsp.getPrimaryServerThisUpdateMaxAge(),
                    ocsp.getFallbackServerThisUpdateMaxAge(),
                    true
            );

            log.info("Using ResilientOcspCertificateRevocationChecker for OCSP");
            return validatorBuilder
                    .withCertificateRevocationChecker(ocspRevocationChecker)
                    .build();
        } catch (JceException | URISyntaxException | OCSPCertificateException e) {
            throw new RuntimeException("Error building the Web eID auth token validator.", e);
        }
    }

    private static AiaOcspServiceConfiguration getAiaOcspServiceConfiguration(AuthConfigurationProperties.Ocsp ocsp,
                                                                              Set<TrustAnchor> trustedCACertificateAnchors,
                                                                              CertStore trustedCACertificateCertStore) throws JceException {
        List<X500Name> nonceDisabledIssuerDNs = ocsp.getCertificateChains().stream()
                .filter(certificateChain -> !certificateChain.getPrimaryServer().isNonceEnabled())
                .map(AuthConfigurationProperties.CertificateChain::getIssuerDn)
                .toList();

        return new AiaOcspServiceConfiguration(
                nonceDisabledIssuerDNs,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore
        );
    }

    private static List<FallbackOcspServiceConfiguration> getFallbackOcspServiceConfigurations(
            IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
            Set<TrustAnchor> trustedCACertificateAnchors,
            CertStore trustedCACertificateCertStore,
            Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap,
            ValidatorType validatorType
    ) throws OCSPCertificateException, JceException {

        if (validatorType == ValidatorType.EIDAS_PROXY) {
            return getEidasProxyFallbackOcspServiceConfigurations(
                    idCardAuthConfigurationProperties,
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore,
                    ocspResponderTrustedCertificatesMap
            );
        }

        return getFallbackOcspServiceConfigurations(
                idCardAuthConfigurationProperties,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore,
                ocspResponderTrustedCertificatesMap
        );
    }

    private static List<FallbackOcspServiceConfiguration> getFallbackOcspServiceConfigurations(IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                                                               Set<TrustAnchor> trustedCACertificateAnchors,
                                                                                               CertStore trustedCACertificateCertStore,
                                                                                               Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap
    ) throws OCSPCertificateException, JceException {
        List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurationList = new ArrayList<>();

        for (AuthConfigurationProperties.CertificateChain chain : idCardAuthConfigurationProperties.getOcsp().getCertificateChains()) {
            X500Name issuerDn = chain.getIssuerDn();
            AuthConfigurationProperties.FallbackOcspServer firstFallbackServer = chain.getFirstFallbackServer();

            if (firstFallbackServer == null) {
                log.info("No fallback configurations found for issuer {}", issuerDn);
                continue;
            }

            AuthConfigurationProperties.FallbackOcspServer secondFallbackServer = chain.getSecondFallbackServer();
            FallbackOcspServiceConfiguration secondFallbackConfiguration = null;
            if (secondFallbackServer != null) {
                secondFallbackConfiguration = new FallbackOcspServiceConfiguration(
                        URI.create(secondFallbackServer.getUrl()),
                        getResponderCertificate(secondFallbackServer, ocspResponderTrustedCertificatesMap),
                        secondFallbackServer.isNonceEnabled(),
                        null,
                        issuerDn,
                        trustedCACertificateAnchors,
                        trustedCACertificateCertStore
                );
            }

            FallbackOcspServiceConfiguration firstFallbackConfiguration = new FallbackOcspServiceConfiguration(
                    URI.create(firstFallbackServer.getUrl()),
                    getResponderCertificate(firstFallbackServer, ocspResponderTrustedCertificatesMap),
                    firstFallbackServer.isNonceEnabled(),
                    secondFallbackConfiguration,
                    issuerDn,
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore
            );
            log.info("Found first fallback configuration for issuer {}", issuerDn);
            logFallbackOcspServiceConfiguration(firstFallbackConfiguration);
            if (secondFallbackConfiguration != null) {
                log.info("Found second fallback configuration for issuer {}", issuerDn);
                logFallbackOcspServiceConfiguration(secondFallbackConfiguration);
            }
            fallbackOcspServiceConfigurationList.add(firstFallbackConfiguration);
        }
        return fallbackOcspServiceConfigurationList;
    }

    private static List<FallbackOcspServiceConfiguration> getEidasProxyFallbackOcspServiceConfigurations(
            IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
            Set<TrustAnchor> trustedCACertificateAnchors,
            CertStore trustedCACertificateCertStore,
            Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap
    ) throws OCSPCertificateException, JceException {
        List<FallbackOcspServiceConfiguration> result = new ArrayList<>();

        for (AuthConfigurationProperties.CertificateChain chain : idCardAuthConfigurationProperties.getOcsp().getCertificateChains()) {
            FallbackOcspServiceConfiguration fallbackConfiguration = buildEidasProxyFallbackConfiguration(
                    chain,
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore,
                    ocspResponderTrustedCertificatesMap
            );

            if (fallbackConfiguration != null) {
                result.add(fallbackConfiguration);
            }
        }

        return result;
    }

    private static FallbackOcspServiceConfiguration buildEidasProxyFallbackConfiguration(
            AuthConfigurationProperties.CertificateChain chain,
            Set<TrustAnchor> trustedCACertificateAnchors,
            CertStore trustedCACertificateCertStore,
            Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap
    ) throws OCSPCertificateException {
        X500Name issuerDn = chain.getIssuerDn();

        FallbackOcspServiceConfiguration secondFallbackConfiguration = createEidasProxyFallbackConfiguration(
                chain.getSecondFallbackServer(),
                null,
                issuerDn,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore,
                ocspResponderTrustedCertificatesMap
        );

        return createEidasProxyFallbackConfiguration(
                chain.getFirstFallbackServer(),
                secondFallbackConfiguration,
                issuerDn,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore,
                ocspResponderTrustedCertificatesMap
        );
    }

    private static FallbackOcspServiceConfiguration createEidasProxyFallbackConfiguration(
            AuthConfigurationProperties.FallbackOcspServer fallbackServer,
            FallbackOcspServiceConfiguration nextFallbackConfiguration,
            X500Name issuerDn,
            Set<TrustAnchor> trustedCACertificateAnchors,
            CertStore trustedCACertificateCertStore,
            Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap
    ) throws OCSPCertificateException {
        if (fallbackServer == null || !fallbackServer.isEnabledForEidasProxy()) {
            return nextFallbackConfiguration;
        }

        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
                URI.create(fallbackServer.getUrl()),
                getResponderCertificate(fallbackServer, ocspResponderTrustedCertificatesMap),
                fallbackServer.isNonceEnabled(),
                nextFallbackConfiguration,
                issuerDn,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore
        );

        log.info("Found eIDAS proxy fallback configuration for issuer {}", issuerDn);
        logFallbackOcspServiceConfiguration(configuration);

        return configuration;
    }

    private static X509Certificate getResponderCertificate(AuthConfigurationProperties.FallbackOcspServer fallbackOcspServer,
                                                           Map<X500Name, X509Certificate> ocspResponderTrustedCertificatesMap) {
        return fallbackOcspServer.getResponderSubjectDn() != null
                ? ocspResponderTrustedCertificatesMap.get(fallbackOcspServer.getResponderSubjectDn())
                : null;
    }

    private static void logFallbackOcspServiceConfiguration(FallbackOcspServiceConfiguration configuration) {
        String nextFallbackAccessLocation = null;
        if (configuration.getNextFallbackConfiguration() != null
                && configuration.getNextFallbackConfiguration().getAccessLocation() != null) {
            nextFallbackAccessLocation = configuration.getNextFallbackConfiguration().getAccessLocation().toString();
        }
        log.info("Created a fallback configuration. Fallback URL: {}, next fallback URL: {}, does support nonce: {}",
                configuration.getAccessLocation(),
                nextFallbackAccessLocation,
                configuration.doesSupportNonce()
        );
    }

    private static KeyStore buildKeystore(ResourceLoader resourceLoader,
                                          AuthConfigurationProperties.TruststoreConfigurationProperties trustStore) {
        try {
            KeyStore keystore = KeyStore.getInstance(trustStore.getType());
            Resource resource = resourceLoader.getResource(trustStore.getPath());
            try (InputStream inputStream = resource.getInputStream()) {
                keystore.load(inputStream, trustStore.getPassword().toCharArray());
            }
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load truststore of type " + trustStore.getType() + " from " + trustStore.getPath() + "!", e);
        }
    }

    private static Map<String, X509Certificate> buildIssuerTrustedCertificatesMap(KeyStore keystore) {
        try {
            PKIXParameters params = new PKIXParameters(keystore);
            return params.getTrustAnchors().stream()
                    .collect(toMap(trustAnchor -> X509Utils.getSubjectCNFromCertificate(trustAnchor.getTrustedCert()), TrustAnchor::getTrustedCert));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: " + e.getMessage(), e);
        }
    }

    private static Map<X500Name, X509Certificate> buildOcspResponderTrustedCertificatesMap(KeyStore keystore) {
        try {
            PKIXParameters params = new PKIXParameters(keystore);
            return params.getTrustAnchors().stream()
                    .collect(toMap(trustAnchor -> X509Utils.getSubjectDN(trustAnchor.getTrustedCert()), TrustAnchor::getTrustedCert));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: " + e.getMessage(), e);
        }
    }

    private static void logIssuerTrustedCertificatesMap(Map<String, X509Certificate> trustedCertificates) {
        trustedCertificates.forEach((subjectCn, certificate) ->
                logTrustedCertificate(subjectCn, certificate, "issuer"));
    }

    private static void logOcspResponderTrustedCertificatesMap(Map<X500Name, X509Certificate> trustedCertificates) {
        trustedCertificates.forEach((subjectDn, certificate) ->
                logTrustedCertificate(X509Utils.getFirstCNFromX500Name(subjectDn), certificate, "OCSP responder"));
    }

    private static void logTrustedCertificate(String subjectCn, X509Certificate certificate, String certificateType) {
        log.info("Trusted {} certificate added to configuration - CN: {}, serialnumber: {}, validFrom: {}, validTo: {}",
                certificateType,
                value("x509.subject.common_name", subjectCn),
                value("x509.serial_number", certificate.getSerialNumber().toString(16)),
                value("x509.not_before", certificate.getNotBefore()),
                value("x509.not_after", certificate.getNotAfter()));
    }
}
