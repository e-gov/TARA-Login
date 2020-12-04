package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.*;
import java.util.stream.Collectors;

@ConfigurationProperties(prefix = "tara")
@Validated
@Slf4j
@Data
public class AuthConfigurationProperties {

    @Pattern(regexp = "(et|en|ru)", message = "invalid default locale value, accepted values are: et, en, ru")
    String defaultLocale = "et";

    List<AuthenticationType> defaultAuthenticationMethods = Arrays.asList(
            AuthenticationType.IDCard,
            AuthenticationType.MobileID);

    HydraConfigurationProperties hydraService = new HydraConfigurationProperties();

    TruststoreProperties tls = new TruststoreProperties();

    Map<AuthenticationType, AuthMethodProperties> authMethods = new HashMap<>();

    @Data
    @ToString
    @Component
    @Validated
    @ConfigurationProperties(prefix = "tara.hydra-service")
    public static class HydraConfigurationProperties {
        @NotBlank
        String loginUrl;
        @NotBlank
        String acceptLoginUrl;
        @NotBlank
        String acceptConsentUrl;
        @NotBlank
        String healthUrl;
        int requestTimeoutInSeconds = 3;
    }

    @Data
    @ToString
    @Validated
    @ConfigurationProperties(prefix = "tara.tls")
    public static class TruststoreProperties {
        @NotBlank
        String truststoreLocation;
        @NotBlank
        String truststorePassword;
        String trustStoreType = "PKCS12";
    }

    @Data
    @ToString
    @ConfigurationProperties
    public static class AuthMethodProperties {
        @NotNull
        LevelOfAssurance levelOfAssurance;
        boolean enabled = true;
    }

    @Data
    @ToString
    @Component
    @Validated
    @ConfigurationProperties(prefix = "tara.auth-methods.mobile-id")
    public static class MidAuthConfigurationProperties extends AuthMethodProperties {
        @NotNull
        String hostUrl;
        @NotNull
        String truststorePath;
        @NotNull
        String truststoreType;
        @NotNull
        String truststorePassword;
        @NotNull
        String relyingPartyUuid;
        @NotNull
        String relyingPartyName;
        @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
        String hashType = "SHA256";
        int longPollingTimeoutSeconds = 30;
        int connectionTimeoutMilliseconds = 5000;
        int readTimeoutMilliseconds = 30000;
        int intervalBetweenSessionStatusQueriesInMilliseconds = 5000;
    }

    @Data
    @ToString
    @Component
    @Validated
    @ConfigurationProperties(prefix = "tara.auth-methods.id-card")
    public static class IdCardAuthConfigurationProperties extends AuthMethodProperties {

        @NotNull
        private String truststorePath;
        private String truststoreType = "PKCS12";
        @NotNull
        private String truststorePassword;
        @Valid
        private List<Ocsp> ocsp;
        @Valid
        private List<Ocsp> fallbackOcsp;
        @PostConstruct
        public void validateConfiguration() {
            if (this.enabled) {
                Assert.notEmpty(ocsp, "At least one ocsp configuration must be defined!");
                Set<String> duplicateNames = getFindDuplicateConfigurations();
                Assert.isTrue(duplicateNames.isEmpty(), "Multiple OCSP configurations detected for issuer's with CN's: " + duplicateNames + ". Please check your configuration!");
                Assert.notNull(this.truststorePath, "Keystore location cannot be empty when OCSP is enabled!");
                Assert.notNull(this.truststorePassword, "Keystore password cannot be empty when OCSP is enabled!");

            } else {
                log.warn("OCSP verification has been DISABLED! User certificates will not be checked for revocation!");
            }
            log.info("Using id-card configuration: " + this);
        }

        private Set<String> getFindDuplicateConfigurations() {
            Set<String> names = new HashSet<>();
            return ocsp.stream()
                    .flatMap(item -> item.getIssuerCn().stream())
                    .filter(cn -> !names.add(cn))
                    .collect(Collectors.toSet());
        }
    }

    @Data
    @NoArgsConstructor
    @ToString
    @Component
    public static class Ocsp {
        public static final long DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS = 2L;
        public static final long DEFAULT_RESPONSE_LIFETIME_IN_SECONDS = 900L;
        public static final int DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS = 3 * 1000;
        public static final int DEFAULT_READ_TIMEOUT_IN_MILLISECONDS = 3 * 1000;

        @NotEmpty
        private List<String> issuerCn;
        @NotEmpty
        private String url;
        private boolean nonceDisabled = false;
        @Min(0L)
        private long acceptedClockSkewInSeconds = DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS;
        @Min(0L)
        private long responseLifetimeInSeconds = DEFAULT_RESPONSE_LIFETIME_IN_SECONDS;
        @Min(0L)
        private int connectTimeoutInMilliseconds = DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS;
        @Min(0L)
        private int readTimeoutInMilliseconds = DEFAULT_READ_TIMEOUT_IN_MILLISECONDS;
        private String responderCertificateCn;
    }

    @Data
    @ToString
    @Component
    public static class HealthConfigurationProperties {

        private int expirationWarningPeriodInDays = 30;
    }
}


