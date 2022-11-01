package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.utils.X509Utils;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

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
    public AuthTokenValidator validator(IdCardAuthConfigurationProperties configurationProvider, Map<String, X509Certificate> trustedCertificatesMap) {
        X509Certificate[] certificates = trustedCertificatesMap.values().toArray(new X509Certificate[0]);
        try {
            return new AuthTokenValidatorBuilder()
                    .withSiteOrigin(configurationProvider.getSiteOrigin().toURI())
                    .withTrustedCertificateAuthorities(certificates)
                    // TARA is using customized OCSP validation instead of AuthTokenValidator's built-in check
                    .withoutUserCertificateRevocationCheckWithOcsp()
                    .build();
        } catch (JceException | URISyntaxException e) {
            throw new RuntimeException("Error building the Web eID auth token validator.", e);
        }
    }
}
