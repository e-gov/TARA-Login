package ee.ria.taraauthserver.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.auth-methods.eidas")
public class EidasConfigurationProperties {

    @NotNull
    LevelOfAssurance levelOfAssurance;

    boolean enabled = true;

    int refreshCountriesInterval = 300000;

    List<String> countries;

    @NotNull
    private String clientUrl;
}
