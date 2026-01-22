package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.utils.X509Utils;
import eu.webeid.security.ResilientOcspRevocationChecker;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspClientImpl;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.security.validator.ocsp.service.FallbackOcspServiceConfiguration;
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
    KeyStore idcardKeystore(ResourceLoader resourceLoader, IdCardAuthConfigurationProperties configurationProvider) {
        try {
            KeyStore keystore = KeyStore.getInstance(configurationProvider.getTruststoreType());
            Resource resource = resourceLoader.getResource(configurationProvider.getTruststorePath());
            try (InputStream inputStream = resource.getInputStream()) {
                keystore.load(inputStream, configurationProvider.getTruststorePassword().toCharArray());
            }
            return keystore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load truststore of type " + configurationProvider.getTruststoreType() + " from " + configurationProvider.getTruststorePath() + "!", e);
        }
    }

    @Bean
    public Map<String, X509Certificate> idCardTrustedCertificatesMap(KeyStore idcardKeystore) {
        try {
            PKIXParameters params = new PKIXParameters(idcardKeystore);
            Map<String, X509Certificate> trustedCertificates = params.getTrustAnchors().stream()
                    .collect(toMap(trustAnchor -> X509Utils.getSubjectCNFromCertificate(trustAnchor.getTrustedCert()), TrustAnchor::getTrustedCert));
            trustedCertificates.forEach((key, value) -> log.info("Trusted OCSP responder certificate added to configuration - CN: {}, serialnumber: {}, validFrom: {}, validTo: {}",
                    value("x509.subject.common_name", key),
                    value("x509.serial_number", value.getSerialNumber().toString()),
                    value("x509.not_before", value.getNotBefore()),
                    value("x509.not_after", value.getNotAfter())));
            return trustedCertificates;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: " + e.getMessage(), e);
        }
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
                                        Map<String, X509Certificate> trustedCertificatesMap) {
        X509Certificate[] certificates = trustedCertificatesMap.values().toArray(new X509Certificate[0]);

        Duration ocspRequestTimeout = Duration.ofSeconds(5);

        // TODO AUT-2547 Move these to AuthConfigurationProperties.
        int slidingWindowSize = CircuitBreakerConfig.DEFAULT_SLIDING_WINDOW_SIZE;
        int minimumNumberOfCalls = CircuitBreakerConfig.DEFAULT_MINIMUM_NUMBER_OF_CALLS;
        int failureRateThreshold = CircuitBreakerConfig.DEFAULT_FAILURE_RATE_THRESHOLD;
        int permittedNumberOfCallsInHalfOpenState = CircuitBreakerConfig.DEFAULT_PERMITTED_CALLS_IN_HALF_OPEN_STATE;
        Duration waitDurationInOpenState = Duration.ofSeconds(CircuitBreakerConfig.DEFAULT_WAIT_DURATION_IN_OPEN_STATE);

        Duration retryWaitDuration = Duration.ofMillis(RetryConfig.DEFAULT_WAIT_DURATION);
        int retryMaxAttempts = 2;

        Duration allowedOcspResponseTimeSkew = Duration.ofMinutes(15);
        // TODO There should be two separate values here.
        Duration maxOcspResponseThisUpdateAge = Duration.ofMinutes(2);
        boolean rejectUnknownOcspResponseStatus = true;

        try {
            AiaOcspServiceConfiguration aiaOcspServiceConfiguration
                    = getAiaOcspServiceConfiguration(idCardAuthConfigurationProperties, trustedCertificatesMap);

            List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations
                    = getFallbackOcspServiceConfigurations(idCardAuthConfigurationProperties, trustedCertificatesMap);

            OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
                    null,
                    aiaOcspServiceConfiguration,
                    fallbackOcspServiceConfigurations
            );

            OcspClient ocspClient = OcspClientImpl.build(ocspRequestTimeout);

            CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
                    .slidingWindowSize(slidingWindowSize)
                    .minimumNumberOfCalls(minimumNumberOfCalls)
                    .failureRateThreshold(failureRateThreshold)
                    .permittedNumberOfCallsInHalfOpenState(permittedNumberOfCallsInHalfOpenState)
                    .waitIntervalFunctionInOpenState(IntervalFunction.of(waitDurationInOpenState))
                    .build();

            RetryConfig retryConfig = RetryConfig.custom()
                    .waitDuration(retryWaitDuration)
                    .maxAttempts(retryMaxAttempts)
                    .build();

            ResilientOcspRevocationChecker ocspRevocationChecker = new ResilientOcspRevocationChecker(
                    ocspClient,
                    ocspServiceProvider,
                    circuitBreakerConfig,
                    retryConfig,
                    allowedOcspResponseTimeSkew,
                    maxOcspResponseThisUpdateAge,
                    rejectUnknownOcspResponseStatus
            );

            return new AuthTokenValidatorBuilder()
                    .withSiteOrigin(authConfigurationProperties.getSiteOrigin().toURI())
                    .withTrustedCertificateAuthorities(certificates)
                    .withOcspCertificateRevocationChecker(ocspRevocationChecker)
                    .build();
        } catch (JceException | URISyntaxException | OCSPCertificateException e) {
            throw new RuntimeException("Error building the Web eID auth token validator.", e);
        }
    }

    private static AiaOcspServiceConfiguration getAiaOcspServiceConfiguration(IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                                             Map<String, X509Certificate> trustedCertificatesMap) throws JceException {
        List<URI> nonceDisabledOcspUrls = idCardAuthConfigurationProperties.getOcsp().stream()
                .filter(AuthConfigurationProperties.Ocsp::isNonceDisabled)
                .map(ocsp -> URI.create(ocsp.getUrl()))
                .toList();

        Set<TrustAnchor> trustedCACertificateAnchors = CertificateValidator
                .buildTrustAnchorsFromCertificates(trustedCertificatesMap.values());
        CertStore trustedCACertificateCertStore = CertificateValidator
                .buildCertStoreFromCertificates(trustedCertificatesMap.values());
        return new AiaOcspServiceConfiguration(
                nonceDisabledOcspUrls,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore
        );
    }

    private static List<FallbackOcspServiceConfiguration> getFallbackOcspServiceConfigurations(IdCardAuthConfigurationProperties idCardAuthConfigurationProperties,
                                                       Map<String, X509Certificate> trustedCertificatesMap) throws OCSPCertificateException {
        List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations = new ArrayList<>();

        for (AuthConfigurationProperties.Ocsp fallback : idCardAuthConfigurationProperties.getFallbackOcsp()) {
            if (fallback.getResponderCertificateCn() == null) {
                // TODO Throw an exception
                continue;
            }
            for (String issuerCn : fallback.getIssuerCn()) {
                AuthConfigurationProperties.Ocsp primary = idCardAuthConfigurationProperties.getOcsp().stream()
                        .filter(ocsp -> ocsp.getIssuerCn().contains(issuerCn))
                        // TODO What if there are multiple entries?
                        .findFirst()
                        .orElse(null);
                if (primary == null) {
                    // TODO Throw an exception
                    continue;
                }
                X509Certificate responderCertificate = trustedCertificatesMap.get(fallback.getResponderCertificateCn());
                FallbackOcspServiceConfiguration fallbackOcspServiceConfiguration = new FallbackOcspServiceConfiguration(
                        URI.create(primary.getUrl()),
                        URI.create(fallback.getUrl()),
                        responderCertificate,
                        !fallback.isNonceDisabled()
                );
                log.info("Created a fallback configuration. Primary URL: {}, fallback URL: {}, does support nonce: {}", fallbackOcspServiceConfiguration.getOcspServiceAccessLocation(), fallbackOcspServiceConfiguration.getFallbackOcspServiceAccessLocation(), fallbackOcspServiceConfiguration.doesSupportNonce());
                fallbackOcspServiceConfigurations.add(fallbackOcspServiceConfiguration);
            }
        }
        return fallbackOcspServiceConfigurations;
    }
}
