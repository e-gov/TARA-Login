package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.eudi.AuthEudiService;
import ee.ria.taraauthserver.authentication.eudi.EudiDigitalCredentialsController;
import ee.ria.taraauthserver.authentication.eudi.EudiWeb2AppController;
import ee.ria.taraauthserver.authentication.eudi.EudiploClient;
import ee.ria.taraauthserver.config.properties.EudiConfigurationProperties;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eudi-wallet.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class EudiConfigurationDisabledTest extends DisabledConfigurationTest {

    @Test
    @Tag(value = "EUDI_AUTH_ENABLED")
    public void whenEudiWalletDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(EudiConfiguration.class);
        assertBeanNotInitiated(EudiConfigurationProperties.class);
        assertBeanNotInitiated("eudiploRestClient");
        assertBeanNotInitiated(EudiploClient.class);
        assertBeanNotInitiated(EudiWeb2AppController.class);
        assertBeanNotInitiated(EudiDigitalCredentialsController.class);
        assertBeanNotInitiated(AuthEudiService.class);
    }
}
