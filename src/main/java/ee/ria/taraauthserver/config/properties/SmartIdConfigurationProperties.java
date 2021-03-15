package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.auth-methods.smart-id")
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class SmartIdConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    @NotNull
    LevelOfAssurance levelOfAssurance;

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

    private int readTimeoutMilliseconds = 30000;

    private int delayStatusPollingStartInMilliseconds = 500;
}