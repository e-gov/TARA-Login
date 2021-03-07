package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.alerts")
public class AlertsConfigurationProperties {

    @NotNull
    private String hostUrl;

    private int connectionTimeoutMilliseconds = 3000;

    private int readTimeoutMilliseconds = 3000;

    private int refreshAlertsIntervalInMilliseconds;

    private int alertsCacheDurationInSeconds = 3600;

}
