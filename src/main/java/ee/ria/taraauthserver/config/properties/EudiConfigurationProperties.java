package ee.ria.taraauthserver.config.properties;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import static net.logstash.logback.marker.Markers.append;

@Data
@Validated
@Slf4j
@EqualsAndHashCode(callSuper = true)
@ConfigurationProperties(prefix = "tara.auth-methods.eudi-wallet")
@ConditionalOnProperty(value = "tara.auth-methods.eudi-wallet.enabled")
public class EudiConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    @NotBlank
    private String eudiploUrl;

    @NotBlank
    private String clientId;

    @NotBlank
    @ToString.Exclude
    private String clientSecret;

    @Positive
    private int connectionTimeoutMilliseconds = 5000;

    @Positive
    private int readTimeoutMilliseconds = 10000;

    @Positive
    private int maxConnectionsTotal = 50;

    @PostConstruct
    public void validateConfiguration() {
        Assert.notNull(getLevelOfAssurance(), "EUDI wallet level of assurance must be configured");
        log.info(append("tara.conf.auth-methods.eudi-wallet.eudiplo_url", eudiploUrl)
                        .and(append("tara.conf.auth-methods.eudi-wallet.client_id", clientId)),
                "Using EUDI wallet configuration");
    }

}
