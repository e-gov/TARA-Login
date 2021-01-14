package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static java.util.List.of;

@Slf4j
@Data
@Validated
@ConfigurationProperties(prefix = "tara")
public class AuthConfigurationProperties {
    public static final String DEFAULT_CONTENT_SECURITY_POLICY = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content";

    @Pattern(regexp = "(et|en|ru)", message = "invalid default locale value, accepted values are: et, en, ru")
    private String defaultLocale = "et";

    @NotEmpty
    private String contentSecurityPolicy = DEFAULT_CONTENT_SECURITY_POLICY;

    private List<AuthenticationType> defaultAuthenticationMethods = of(ID_CARD, MOBILE_ID);

    private HydraConfigurationProperties hydraService = new HydraConfigurationProperties();

    private TruststoreProperties tls = new TruststoreProperties();

    private EnumMap<AuthenticationType, AuthMethodProperties> authMethods = new EnumMap<>(AuthenticationType.class);

    @Data
    @Validated
    @ConfigurationProperties(prefix = "tara.hydra-service")
    public static class HydraConfigurationProperties {

        @NotBlank
        private String loginUrl;

        @NotBlank
        private String acceptLoginUrl;

        @NotBlank
        private String acceptConsentUrl;

        @NotBlank
        private String healthUrl;

        @NotBlank
        private String rejectConsentUrl;

        @NotBlank
        private String rejectLoginUrl;

        private int requestTimeoutInSeconds = 3;
    }

    @Data
    @Validated
    @ConfigurationProperties(prefix = "tara.tls")
    public static class TruststoreProperties {

        @NotBlank
        private String truststoreLocation;

        @NotBlank
        private String truststorePassword;

        private String trustStoreType = "PKCS12";
    }

    @Data
    public static class AuthMethodProperties {

        @NotNull
        LevelOfAssurance levelOfAssurance;

        boolean enabled = true;
    }

    @Data
    @Validated
    @EqualsAndHashCode(callSuper = true)
    @ConfigurationProperties(prefix = "tara.auth-methods.mobile-id")
    public static class MidAuthConfigurationProperties extends AuthMethodProperties {

        @NotNull
        private String hostUrl;

        @NotNull
        private String truststorePath;

        @NotNull
        private String truststoreType;

        @NotNull
        private String truststorePassword;

        @NotNull
        private String relyingPartyUuid;

        @NotNull
        private String relyingPartyName;

        @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
        private String hashType = "SHA256";

        private int longPollingTimeoutSeconds = 30;

        private int connectionTimeoutMilliseconds = 5000;

        private int readTimeoutMilliseconds = 30000;

        private int intervalBetweenSessionStatusQueriesInMilliseconds = 5000;
    }

    @Data
    @Validated
    @EqualsAndHashCode(callSuper = true)
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
            if (isEnabled()) {
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
    public static class Ocsp {
        public static final long DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS = 2L;
        public static final long DEFAULT_RESPONSE_LIFETIME_IN_SECONDS = 900L;
        public static final int DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS = 3 * 1000;
        public static final int DEFAULT_READ_TIMEOUT_IN_MILLISECONDS = 3 * 1000;

        @NotEmpty
        private List<String> issuerCn;

        @NotEmpty
        private String url;

        @Getter
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
    @ConfigurationProperties(prefix = "tara.health-endpoint")
    public static class HealthConfigurationProperties {

        private int expirationWarningPeriodInDays = 30;
    }
}
