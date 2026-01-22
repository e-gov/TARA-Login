package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.utils.X509Utils;
import eu.webeid.ocsp.client.OcspClient;
import eu.webeid.ocsp.client.OcspClientImpl;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import eu.webeid.resilientocsp.service.FallbackOcspServiceConfiguration;
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

        try {
            AuthTokenValidatorBuilder validatorBuilder = new AuthTokenValidatorBuilder()
                    .withSiteOrigin(authConfigurationProperties.getSiteOrigin().toURI())
                    .withTrustedCertificateAuthorities(certificates);

            AuthConfigurationProperties.Ocsp ocsp = idCardAuthConfigurationProperties.getOcsp();

            if (!ocsp.isEnabled()) {
                log.info("OCSP check is disabled");
                return validatorBuilder
                        .withoutUserCertificateRevocationCheck()
                        .build();
            }

            AiaOcspServiceConfiguration aiaOcspServiceConfiguration
                    = getAiaOcspServiceConfiguration(ocsp, trustedCertificatesMap);

            List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations
                    = getFallbackOcspServiceConfigurations(idCardAuthConfigurationProperties, trustedCertificatesMap);

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
                                                                              Map<String, X509Certificate> trustedCertificatesMap) throws JceException {
        // TODO Handle URLs ending/not ending with a slash
        List<URI> nonceDisabledOcspUrls = ocsp.getCertificateChains().stream()
                .filter(certificateChain -> !certificateChain.getPrimaryServer().isNonceEnabled())
                .map(certificateChain -> URI.create(certificateChain.getPrimaryServer().getUrl()))
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
        List<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurationList = new ArrayList<>();

        for (AuthConfigurationProperties.CertificateChain chain : idCardAuthConfigurationProperties.getOcsp().getCertificateChains()) {
            String issuerCn = chain.getIssuerCn();
            AuthConfigurationProperties.FallbackOcspServer firstFallbackServer = chain.getFirstFallbackServer();

            if (firstFallbackServer == null) {
                log.info("No fallback configurations found for issuer {}", issuerCn);
                continue;
            }

            FallbackOcspServiceConfiguration firstFallbackConfiguration = new FallbackOcspServiceConfiguration(
                    URI.create(chain.getPrimaryServer().getUrl()),
                    URI.create(firstFallbackServer.getUrl()),
                    trustedCertificatesMap.get(getResponderCertificateCn(firstFallbackServer, chain)),
                    firstFallbackServer.isNonceEnabled()
            );
            log.info("Found first fallback configuration for issuer {}", issuerCn);
            logFallbackOcspServiceConfiguration(firstFallbackConfiguration);
            fallbackOcspServiceConfigurationList.add(firstFallbackConfiguration);

            AuthConfigurationProperties.FallbackOcspServer secondFallbackServer = chain.getSecondFallbackServer();
            if (secondFallbackServer == null) {
                continue;
            }

            FallbackOcspServiceConfiguration secondFallbackConfiguration = new FallbackOcspServiceConfiguration(
                    URI.create(firstFallbackServer.getUrl()),
                    URI.create(secondFallbackServer.getUrl()),
                    trustedCertificatesMap.get(getResponderCertificateCn(secondFallbackServer, chain)),
                    secondFallbackServer.isNonceEnabled()
            );
            log.info("Found second fallback configuration for issuer {}", issuerCn);
            logFallbackOcspServiceConfiguration(secondFallbackConfiguration);
            fallbackOcspServiceConfigurationList.add(secondFallbackConfiguration);
        }
        return fallbackOcspServiceConfigurationList;
    }

    private static String getResponderCertificateCn(AuthConfigurationProperties.FallbackOcspServer fallbackOcspServer,
                                                    AuthConfigurationProperties.CertificateChain certificateChain) {
        return fallbackOcspServer.getResponderCertificateCn() == null
                ? certificateChain.getIssuerCn()
                : fallbackOcspServer.getResponderCertificateCn();
    }

    private static void logFallbackOcspServiceConfiguration(FallbackOcspServiceConfiguration configuration) {
        log.info("Created a fallback configuration. Primary URL: {}, fallback URL: {}, does support nonce: {}",
                configuration.getOcspServiceAccessLocation(),
                configuration.getFallbackOcspServiceAccessLocation(),
                configuration.doesSupportNonce()
        );
    }
}
