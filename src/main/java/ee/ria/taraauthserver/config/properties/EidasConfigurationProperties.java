package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.auth-methods.eidas")
public class EidasConfigurationProperties {

    boolean enabled = true;

    String scriptHash = "sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=";

    int refreshCountriesIntervalInMilliseconds;

    List<String> availableCountries = new ArrayList<>();

    private int requestTimeoutInSeconds = 3;

    private int readTimeoutInSeconds = 3;

    private int maxConnectionsTotal = 50;

    private int relayStateCacheDurationInSeconds = 300;

    @NotNull
    private String clientUrl;
}
