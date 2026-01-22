package ee.ria.taraauthserver.config.properties;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.retry.RetryConfig;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import java.net.URL;
import java.time.Duration;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.List.of;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Data
@Validated
@ConfigurationProperties(prefix = "tara")
public class AuthConfigurationProperties {
    public static final Set<String> MASKED_FIELD_NAMES = new HashSet<>();
    public static final String DEFAULT_CONTENT_SECURITY_POLICY = "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content";
    public static final String DEFAULT_LOCALE = "et";

    @NotBlank
    private String errorReportEmail;

    @NotEmpty
    private String contentSecurityPolicy = DEFAULT_CONTENT_SECURITY_POLICY;

    private List<AuthenticationType> defaultAuthenticationMethods = of(ID_CARD, MOBILE_ID);

    private HydraConfigurationProperties hydraService = new HydraConfigurationProperties();

    private TlsConfigurationProperties tls = new TlsConfigurationProperties();

    @NotNull
    private URL siteOrigin;

    private EnumMap<AuthenticationType, AuthMethodProperties> authMethods = new EnumMap<>(AuthenticationType.class);

    @NotNull
    private Duration authFlowTimeout;

    @Value("${tara.masked_field_names:session_id}")
    public void setMaskedFieldNames(Set<String> maskedFieldNames) {
        MASKED_FIELD_NAMES.addAll(maskedFieldNames);
    }

    @Data
    @Validated
    @ConfigurationProperties(prefix = "tara.govsso")
    public static class GovSsoConfigurationProperties {

        String selfServiceUrl;
    }

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

        private int maxConnectionsTotal = 50;
    }

    @Data
    @Validated
    @ConfigurationProperties(prefix = "govsso.hydra-service")
    public static class GovSsoHydraConfigurationProperties {

        private String loginUrl;

        private String clientId;
    }

    @Data
    @Validated
    @ConfigurationProperties(prefix = "tara.tls")
    public static class TlsConfigurationProperties {

        @NotBlank
        private String truststoreLocation;

        @NotBlank
        private String truststorePassword;

        private String trustStoreType = "PKCS12";

        @NotBlank
        private String xRoadTruststoreLocation;

        @NotBlank
        private String xRoadTruststorePassword;

        @NotBlank
        private String xRoadKeystoreLocation;

        @NotBlank
        private String xRoadKeystorePassword;

        private String xRoadStoreType = "PKCS12";

        private String defaultProtocol;

        List<@NotBlank String> enabledProtocols;

        List<@NotBlank String> enabledCipherSuites;
    }

    @Data
    public static class AuthMethodProperties {

        // TODO In eIDAS configuration this value is null, but other authentication methods should require non-null value.
        LevelOfAssurance levelOfAssurance;

        boolean enabled = false;
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

        @NotNull
        private String displayText;

        @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
        private String hashType = "SHA256";

        private int longPollingTimeoutSeconds = 30;

        private int connectionTimeoutMilliseconds = 5000;

        private int readTimeoutMilliseconds = 35000;

        private int intervalBetweenSessionStatusQueriesInMilliseconds = 5000;

        private int delayInitiateMidSessionInMilliseconds = 0;

        private int delayStatusPollingStartInMilliseconds = 500;

        public Duration getDelayInitiateMidSession() {
            return Duration.of(delayInitiateMidSessionInMilliseconds, MILLIS);
        }

        public Duration getDelayStatusPollingStart() {
            return Duration.of(delayStatusPollingStartInMilliseconds, MILLIS);
        }

        @PostConstruct
        public void validateConfiguration() {
            Assert.isTrue(readTimeoutMilliseconds >= (longPollingTimeoutSeconds * 1000) + 5000, "Mobile-ID read timeout must be at least 5 seconds longer than its long polling timeout.");
        }
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

        @NotNull
        private Ocsp ocsp;

        @PostConstruct
        public void validateConfiguration() {
            Assert.notNull(this.truststorePath, "Keystore location cannot be empty!");
            Assert.notNull(this.truststorePassword, "Keystore password cannot be empty!");
            log.info(append("tara.conf.auth-methods.id-card", this), "Using id-card configuration");
        }
    }

    @Data
    public static class Ocsp {

        private boolean enabled = true;

        private Duration allowedResponseTimeSkew = Duration.ofMinutes(15);

        private Duration primaryServerThisUpdateMaxAge = Duration.ofMinutes(2);

        private Duration requestTimeout = Duration.ofSeconds(5);

        private OcspRetryConfig retry = new OcspRetryConfig();

        private OcspCircuitBreakerConfig circuitBreaker = new OcspCircuitBreakerConfig();

        @Valid
        private List<CertificateChain> certificateChains;

        @PostConstruct
        public void validateConfiguration() {
            if (this.enabled) {
                Assert.notEmpty(certificateChains, "At least one certificate chain configuration must be defined!");
                Set<String> duplicateNames = getFindDuplicateConfigurations();
                Assert.isTrue(duplicateNames.isEmpty(), "Multiple certificate chain configurations detected for issuer's with CN's: " + duplicateNames + ". Please check your configuration!");
            } else {
                log.warn("OCSP verification has been DISABLED! User certificates will not be checked for revocation!");
            }
        }

        private Set<String> getFindDuplicateConfigurations() {
            Set<String> names = new HashSet<>();
            return certificateChains.stream()
                    .map(CertificateChain::getIssuerCn)
                    .filter(cn -> !names.add(cn))
                    .collect(Collectors.toSet());
        }
    }

    @Data
    public static class OcspRetryConfig {

        private Duration waitDuration = Duration.ofMillis(RetryConfig.DEFAULT_WAIT_DURATION);

        @Positive
        private int maxAttempts = 2;
    }

    @Data
    public static class OcspCircuitBreakerConfig {

        @Positive
        private int slidingWindowSize = CircuitBreakerConfig.DEFAULT_SLIDING_WINDOW_SIZE;

        @Positive
        private int minimumNumberOfCalls = CircuitBreakerConfig.DEFAULT_MINIMUM_NUMBER_OF_CALLS;

        @Min(1)
        @Max(100)
        private int failureRateThreshold = CircuitBreakerConfig.DEFAULT_FAILURE_RATE_THRESHOLD;

        @Positive
        private int permittedNumberOfCallsInHalfOpenState = CircuitBreakerConfig.DEFAULT_PERMITTED_CALLS_IN_HALF_OPEN_STATE;

        private Duration waitDurationInOpenState = Duration.ofSeconds(CircuitBreakerConfig.DEFAULT_WAIT_DURATION_IN_OPEN_STATE);
    }

    @Data
    public static class CertificateChain {

        @NotEmpty
        private String issuerCn;

        @NotNull
        private PrimaryOcspServer primaryServer;

        private FallbackOcspServer firstFallbackServer;

        private FallbackOcspServer secondFallbackServer;

        @PostConstruct
        public void validateConfiguration() {
            Assert.isTrue(secondFallbackServer == null || firstFallbackServer != null, "Second fallback is only allowed when first fallback is set");
        }
    }

    @Data
    public abstract static class OcspServer {

        @NotEmpty
        private String url;

        private boolean nonceEnabled = true;
    }

    public static class PrimaryOcspServer extends OcspServer {
    }

    @EqualsAndHashCode(callSuper = true)
    @Data
    public static class FallbackOcspServer extends OcspServer {

        private String responderCertificateCn;
    }

    @Data
    @ConfigurationProperties(prefix = "tara.health-endpoint")
    public static class HealthConfigurationProperties {

        private int expirationWarningPeriodInDays = 30;
    }

    @Data
    @ConfigurationProperties(prefix = "tara.auth-methods.id-card.filter-for-eidas-proxy")
    public static class FilterForEidasProxy {

        private String clientId;

        private List<String> forbiddenIssuerCns = List.of();
    }
}
