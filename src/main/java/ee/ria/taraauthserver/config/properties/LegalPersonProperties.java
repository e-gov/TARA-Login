package ee.ria.taraauthserver.config.properties;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.legal-person-authentication")
public class LegalPersonProperties {

    private boolean enabled = true;

    @NotNull
    private String xRoadServerUrl;

    private int xRoadServerConnectTimeoutInMilliseconds = 3000;

    private int xRoadServerReadTimeoutInMilliseconds = 3000;

    @NotNull
    private String xRoadServiceInstance;

    @NotNull
    private String xRoadServiceMemberClass;

    @NotNull
    private String xRoadServiceMemberCode;

    @NotNull
    private String xRoadServiceSubsystemCode;

    @NotNull
    private String xRoadClientSubsystemInstance;

    @NotNull
    private String xRoadClientSubsystemMemberClass;

    @NotNull
    private String xRoadClientSubsystemMemberCode;

    @NotNull
    private String xRoadClientSubsystemCode;

    private String[] esindusv2AllowedTypes = new String[]{"TÜ", "UÜ", "OÜ", "AS", "TÜH", "SA", "MTÜ"};
}
