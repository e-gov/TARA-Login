package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.auth-methods.smart-id")
public class SmartIdConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    @NotNull
    private String trustedCaCertificatesLocation;

    @Pattern(regexp = "(SHA256|SHA384|SHA512)", message = "invalid hash value, accepted values are: SHA256, SHA384, SHA512")
    private String hashType = "SHA512";

    @NotNull
    private List<String> trustedCaCertificates = new ArrayList<>();

    @NotNull
    private String relyingPartyUuid;

    @NotNull
    private String relyingPartyName;

    @NotNull
    private String hostUrl;
}
