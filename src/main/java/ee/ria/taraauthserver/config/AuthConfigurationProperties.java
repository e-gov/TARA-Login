package ee.ria.taraauthserver.config;


import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
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
}


