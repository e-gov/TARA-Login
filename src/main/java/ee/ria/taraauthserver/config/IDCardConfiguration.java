package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Map;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static java.util.stream.Collectors.toMap;

@ConditionalOnProperty(value = "id-card.enabled", matchIfMissing = true)
@Configuration
@Slf4j
public class IDCardConfiguration {

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
                    key, value.getSerialNumber(), value.getNotBefore(), value.getNotAfter()));
            return trustedCertificates;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read trusted certificates from id-card truststore: " + e.getMessage(), e);
        }
    }
}
