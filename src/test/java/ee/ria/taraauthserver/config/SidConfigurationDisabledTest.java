package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.smartid.SmartIdController;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.smart-id.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class SidConfigurationDisabledTest extends DisabledConfigurationTest {

    @Test
    @Tag(value = "SID_AUTH_ENABLED")
    public void whenLegalPersonDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(SmartIdController.class);
        assertBeanNotInitiated(SmartIdConfiguration.class);
    }
}
