package ee.ria.taraauthserver.health;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static java.time.Instant.now;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

@Slf4j
@Component
@ConditionalOnProperty(value = "tara.health-endpoint.enabled", matchIfMissing = true)
public class TruststoreHealthIndicator extends AbstractHealthIndicator {

    @Autowired
    ResourceLoader resourceLoader;
    @Autowired
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties idCardConfiguration;
    @Autowired
    private AuthConfigurationProperties.HealthConfigurationProperties healthConfiguration;

    public static final String X_509 = "X.509";
    public static final String TRUSTSTORE_WARNING = "Truststore certificate '%s' with serial number '%s' is expiring at %s";
    private final Map<String, CertificateInfo> trustStoreCertificates = new HashMap<>();

    @Getter
    private Clock systemClock;

    public TruststoreHealthIndicator() {
        super("Truststore certificates expiration check failed");
        this.systemClock = Clock.systemUTC();
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        if (getCertificatesExpiredAt(now(getSystemClock())).isEmpty()) {
            builder.up().withDetails(trustStoreCertificates).build();
        } else {
            builder.down().withDetails(trustStoreCertificates).build();
        }
    }

    public List<String> getCertificateExpirationWarnings() {
        return getCertificatesExpiredAt(now(getSystemClock()).plus(Period.ofDays(healthConfiguration.getExpirationWarningPeriodInDays()))).values().stream()
                .map(certificateInfo -> format(TRUSTSTORE_WARNING, certificateInfo.getSubjectDN(),
                        certificateInfo.getSerialNumber(), certificateInfo.getValidTo()))
                .collect(toList());
    }

    private Map<String, CertificateInfo> getCertificatesExpiredAt(Instant expired) {
        Map<String, CertificateInfo> test = trustStoreCertificates.entrySet().stream()
                .filter(es -> expired.isAfter(es.getValue().validTo))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
        return trustStoreCertificates.entrySet().stream()
                .filter(es -> expired.isAfter(es.getValue().validTo))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @PostConstruct
    private void setupTruststoreCertificatesInfo() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(idCardConfiguration.getTruststoreType());
        Resource resource = resourceLoader.getResource(idCardConfiguration.getTruststore());
        keyStore.load(resource.getInputStream(), idCardConfiguration.getTruststorePassword().toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                Certificate certificate = keyStore.getCertificate(alias);
                if (X_509.equals(certificate.getType())) {
                    X509Certificate x509 = (X509Certificate) certificate;
                    trustStoreCertificates.put(alias, CertificateInfo.builder()
                            .validTo(x509.getNotAfter().toInstant())
                            .subjectDN(x509.getSubjectDN().getName())
                            .serialNumber(x509.getSerialNumber().toString())
                            .build());
                }
            }
        }
    }

    @Builder
    @Getter
    public static class CertificateInfo {
        private final Instant validTo;
        private final String subjectDN;
        private final String serialNumber;
    }
}