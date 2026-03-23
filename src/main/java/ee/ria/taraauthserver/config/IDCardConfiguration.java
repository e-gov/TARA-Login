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
        Map<String, X509Certificate> trustedCertificates = buildTrustedCertificatesMap(issuerKeystore);
        logTrustedCertificateMap(trustedCertificates, "issuer");
        return trustedCertificates;
    }

    @Bean
    public Map<String, X509Certificate> ocspResponderTrustedCertificatesMap(KeyStore ocspResponderKeystore) {
        Map<String, X509Certificate> trustedCertificates = buildTrustedCertificatesMap(ocspResponderKeystore);
        logTrustedCertificateMap(trustedCertificates, "OCSP responder");
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
    public AuthTokenValidator validator(AuthConfigurationProperties authConfigurationProperties,
                                        IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                        Map<String, X509Certificate> issuerTrustedCertificatesMap,
                                        Map<String, X509Certificate> ocspResponderTrustedCertificatesMap) {
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

            List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations
                    = getFallbackOcspServiceConfigurations(idCardAuthConfigurationProperties, trustedCACertificateAnchors,
                    trustedCACertificateCertStore, ocspResponderTrustedCertificatesMap);

            OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
                    null,
                    aiaOcspServiceConfiguration,
                    fallbackOcspServiceConfigurations
            );

            OcspClient ocspClient = OcspClientImpl.build(ocsp.getRequestTimeout());

            AuthConfigurationProperties.OcspCircuitBreakerConfig ocspCircuitBreakerConfig = ocsp.getCircuitBreaker();
            CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
                    .slidingWindowSize(ocspCircuitBreakerConfig.getSlidingWindowSize())
                    .minimumNumberOfCalls(ocspCircuitBreakerConfig.getMinimumNumberOfCalls())
                    .failureRateThreshold(ocspCircuitBreakerConfig.getFailureRateThreshold())
                    .permittedNumberOfCallsInHalfOpenState(ocspCircuitBreakerConfig.getPermittedNumberOfCallsInHalfOpenState())
                    .waitIntervalFunctionInOpenState(IntervalFunction.of(ocspCircuitBreakerConfig.getWaitDurationInOpenState()))
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
        List<String> nonceDisabledIssuerCNs = ocsp.getCertificateChains().stream()
                .filter(certificateChain -> !certificateChain.getPrimaryServer().isNonceEnabled())
                .map(AuthConfigurationProperties.CertificateChain::getIssuerCn)
                .toList();

        return new AiaOcspServiceConfiguration(
                nonceDisabledIssuerCNs,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore
        );
    }

    private static List<FallbackOcspServiceConfiguration> getFallbackOcspServiceConfigurations(IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                                                               Set<TrustAnchor> trustedCACertificateAnchors,
                                                                                               CertStore trustedCACertificateCertStore,
                                                                                               Map<String, X509Certificate> ocspResponderTrustedCertificatesMap
    ) throws OCSPCertificateException, JceException {
        List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurationList = new ArrayList<>();

        for (AuthConfigurationProperties.CertificateChain chain : idCardAuthConfigurationProperties.getOcsp().getCertificateChains()) {
            String issuerCn = chain.getIssuerCn();
            AuthConfigurationProperties.FallbackOcspServer firstFallbackServer = chain.getFirstFallbackServer();

            if (firstFallbackServer == null) {
                log.info("No fallback configurations found for issuer {}", issuerCn);
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
                        chain.getIssuerCn(),
                        trustedCACertificateAnchors,
                        trustedCACertificateCertStore
                );
            }

            FallbackOcspServiceConfiguration firstFallbackConfiguration = new FallbackOcspServiceConfiguration(
                    URI.create(firstFallbackServer.getUrl()),
                    getResponderCertificate(firstFallbackServer, ocspResponderTrustedCertificatesMap),
                    firstFallbackServer.isNonceEnabled(),
                    secondFallbackConfiguration,
                    chain.getIssuerCn(),
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore
            );
            log.info("Found first fallback configuration for issuer {}", issuerCn);
            logFallbackOcspServiceConfiguration(firstFallbackConfiguration);
            if (secondFallbackConfiguration != null) {
                log.info("Found second fallback configuration for issuer {}", issuerCn);
                logFallbackOcspServiceConfiguration(secondFallbackConfiguration);
            }
            fallbackOcspServiceConfigurationList.add(firstFallbackConfiguration);
        }
        return fallbackOcspServiceConfigurationList;
    }

    private static X509Certificate getResponderCertificate(AuthConfigurationProperties.FallbackOcspServer fallbackOcspServer,
                                                           Map<String, X509Certificate> ocspResponderTrustedCertificatesMap) {
        return fallbackOcspServer.getResponderCertificateCn() != null
                ? ocspResponderTrustedCertificatesMap.get(fallbackOcspServer.getResponderCertificateCn())
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

    private static Map<String, X509Certificate> buildTrustedCertificatesMap(KeyStore keystore) {
        try {
            PKIXParameters params = new PKIXParameters(keystore);
            return params.getTrustAnchors().stream()
                    .collect(toMap(trustAnchor -> X509Utils.getSubjectCNFromCertificate(trustAnchor.getTrustedCert()), TrustAnchor::getTrustedCert));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: " + e.getMessage(), e);
        }
    }

    private static void logTrustedCertificateMap(Map<String, X509Certificate> trustedCertificates, String certificateType) {
        trustedCertificates.forEach((key, value) -> log.info("Trusted {} certificate added to configuration - CN: {}, serialnumber: {}, validFrom: {}, validTo: {}",
                certificateType,
                value("x509.subject.common_name", key),
                value("x509.serial_number", value.getSerialNumber().toString(16)),
                value("x509.not_before", value.getNotBefore()),
                value("x509.not_after", value.getNotAfter())));
    }
}
