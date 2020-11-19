package ee.ria.taraauthserver.config;


import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "tara")
@Validated
@Data
public class AuthConfigurationProperties {

    @Pattern(regexp = "(et|en|ru)", message = "invalid default locale value, accepted values are: et, en, ru")
    String defaultLocale = "et";

    List<AuthenticationType> defaultAuthenticationMethods = Arrays.asList(
            AuthenticationType.IDCard,
            AuthenticationType.MobileID);

    HydraConfigurationProperties hydraService = new HydraConfigurationProperties();

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
        @NotNull
        int requestTimeoutInSeconds = 3;
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
        @NotNull
        @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
        String hashType = "SHA256";
        @NotNull
        int connectionTimeoutMilliseconds = 5000;
        @NotNull
        int readTimeoutMilliseconds = 30000;
    }

    @Data
    @ToString
    @Component
    @Validated
    @ConfigurationProperties(prefix = "tara.auth-methods.id-card")
    public static class IdCardAuthConfigurationProperties {
        public static final long DEFAULT_ACCEPTED_CLOCK_SKEW_IN_SECONDS = 2L;
        public static final long DEFAULT_RESPONSE_LIFETIME_IN_SECONDS = 900L;
        public static final int DEFAULT_CONNECT_TIMEOUT_IN_MILLISECONDS = 3 * 1000;
        public static final int DEFAULT_READ_TIMEOUT_IN_MILLISECONDS = 3 * 1000;

        @NotNull
        private String truststore;
        private String truststoreType = "PKCS12";
        @NotNull
        private String truststorePassword;
        private boolean ocspEnabled = true;

        @Valid
        private List<Ocsp> ocsp;

        @Valid
        private List<Ocsp> fallbackOcsp;
    }

    @Data
    @NoArgsConstructor
    @ToString
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
}


