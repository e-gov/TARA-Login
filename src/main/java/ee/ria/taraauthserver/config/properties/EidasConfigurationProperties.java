package ee.ria.taraauthserver.config.properties;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Validated
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
@ConfigurationProperties(prefix = "tara.auth-methods.eidas")
public class EidasConfigurationProperties extends AuthConfigurationProperties.AuthMethodProperties {

    private String scriptHash = "sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=";

    private int refreshCountriesIntervalInMilliseconds;

    private Map<SPType, List<String>> availableCountries = new HashMap<>();

    private int requestTimeoutInSeconds = 3;

    private int readTimeoutInSeconds = 3;

    private int maxConnectionsTotal = 50;

    private int relayStateCacheDurationInSeconds = 300;

    @NotNull
    private String clientUrl;
}
