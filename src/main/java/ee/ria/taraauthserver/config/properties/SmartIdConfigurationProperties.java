package ee.ria.taraauthserver.config.properties;

import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.utils.Iso3166Alpha2CountryCodes;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import java.net.URL;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoUnit.MILLIS;

@Data
@Validated
@Slf4j
@ConfigurationProperties(prefix = "tara.auth-methods.smart-id")
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class SmartIdConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    @NotNull
    private String relyingPartyUuid;

    @NotNull
    private String relyingPartyName;

    @NotNull
    private String displayText;

    @NotNull
    private String hostUrl;

    @NotNull
    @Valid
    private NotificationBased notificationBased;

    @NotNull
    @Valid
    private Web2App web2app;

    @NotNull
    @Valid
    private QrCode qrCode;

    @NotNull
    @Valid
    private TruststoreConfigurationProperties trustAnchorTruststore;

    @NotNull
    @Valid
    private TruststoreConfigurationProperties intermediateCaTruststore;

    @NotNull
    private String schemaName;

    private int connectionTimeoutMilliseconds = 5000;

    private int readTimeoutMilliseconds = 35000;

    private int longPollingTimeoutMilliseconds = 30000;

    private int delayInitiateSidSessionInMilliseconds = 3000;

    @Iso3166Alpha2CountryCodes
    private Set<String> allowedCountries;

    private int delayStatusPollingStartInMilliseconds = 500;

    public Duration getDelayInitiateSidSession() {
        return Duration.of(delayInitiateSidSessionInMilliseconds, MILLIS);
    }

    public Duration getDelayStatusPollingStart() {
        return Duration.of(delayStatusPollingStartInMilliseconds, MILLIS);
    }

    public boolean isAuthenticationFromCountryAllowed(String country) {
        if (allowedCountries == null || allowedCountries.isEmpty()) {
            return true;
        }
        return allowedCountries.contains(country);
    }

    @PostConstruct
    public void validateConfiguration() {
        Assert.isTrue(readTimeoutMilliseconds >= longPollingTimeoutMilliseconds + 5000, "Smart-ID read timeout must be at least 5 seconds longer than its long polling timeout.");
        Assert.isTrue(notificationBased.isEnabled() || web2app.isEnabled() || qrCode.isEnabled(),
                "If Smart-ID is enabled, then at least one of the Smart-ID authentication flows must be enabled: 'notification-based', 'web2app' or 'qr-code'");
        Assert.isTrue(web2app.isEnabled() == qrCode.isEnabled(),
                "Only enabling one of 'web2app' and 'qr-code' flows is currently not supported");
    }

    public RelyingParty getRelyingParty() {
        return new RelyingParty(relyingPartyName, relyingPartyUuid);
    }

    @Data
    public static class TruststoreConfigurationProperties {

        @NotNull
        private String path;

        @NotNull
        private String type;

        @NotNull
        private String password;
    }

    @Data
    public static class NotificationBased {

        @NotNull
        private boolean enabled;
    }

    @Data
    public static class Web2App {

        @NotNull
        private boolean enabled;

        private int frontendPollingIntervalInMilliseconds = 1000;

        @Valid
        @NotNull
        private Web2AppCustomCallback customCallback;

    }

    @Data
    public static class QrCode {

        @NotNull
        private boolean enabled;
    }

    @Data
    public static class Web2AppCustomCallback {

        @NotNull
        private Boolean enabled;
        @Valid
        private List<Web2AppCustomCallbackClient> clients = List.of();

        @PostConstruct
        public void validateConfiguration() {
            Set<String> duplicateClientIds = getDuplicateClientIds();
            Assert.isTrue(duplicateClientIds.isEmpty(),
                    "Multiple Smart-ID Web2App custom callback registrations for clients: " + duplicateClientIds + ".");
        }

        private Set<String> getDuplicateClientIds() {
            Set<String> seen = new HashSet<>();
            return clients.stream()
                    .map(Web2AppCustomCallbackClient::getClientId)
                    .filter(cn -> !seen.add(cn))
                    .collect(Collectors.toSet());
        }

    }

    @Data
    public static class Web2AppCustomCallbackClient {

        @NotNull
        private String clientId;
        @NotNull
        private URL callbackUrl;
        private boolean authenticationRequestAppFlagRequired = false;

    }


}
