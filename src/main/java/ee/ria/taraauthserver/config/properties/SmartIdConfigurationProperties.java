package ee.ria.taraauthserver.config.properties;

import ee.ria.taraauthserver.authentication.RelyingParty;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@Slf4j
@ConfigurationProperties(prefix = "tara.auth-methods.smart-id")
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class SmartIdConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
    private String hashType = "SHA512";

    @NotNull
    private String relyingPartyUuid;

    @NotNull
    private String relyingPartyName;

    @NotNull
    private String displayText;

    @NotNull
    private String hostUrl;

    @NotNull
    private String truststorePath;

    @NotNull
    private String truststoreType;

    @NotNull
    private String truststorePassword;

    private int connectionTimeoutMilliseconds = 5000;

    private int readTimeoutMilliseconds = 35000;

    private int longPollingTimeoutMilliseconds = 30000;

    private int delayInitiateSidSessionInMilliseconds = 3000;

    private int delayStatusPollingStartInMilliseconds = 500;

    @PostConstruct
    public void validateConfiguration() {
        Assert.isTrue(readTimeoutMilliseconds >= longPollingTimeoutMilliseconds + 5000, "Smart-ID read timeout must be at least 5 seconds longer than its long polling timeout.");
    }

    public RelyingParty getRelyingParty() {
        return new RelyingParty(relyingPartyName, relyingPartyUuid);
    }

}
