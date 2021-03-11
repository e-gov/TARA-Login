package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.eidas.EidasCallbackController;
import ee.ria.taraauthserver.authentication.eidas.EidasController;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class EidasConfigurationDisabledTest extends DisabledConfigurationTest {

    @Test
    @Tag(value = "EIDAS_AUTH_ENABLED")
    public void whenEidasAuthenticationMethodIsDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(EidasConfiguration.class);
        assertBeanNotInitiated(EidasConfigurationProperties.class);
        assertBeanNotInitiated(EidasController.class);
        assertBeanNotInitiated(EidasCallbackController.class);
    }
}