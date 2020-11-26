package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.controllers.AuthMidController;
import ee.ria.taraauthserver.controllers.IdCardController;
import ee.ria.taraauthserver.utils.OCSPConfigurationResolver;
import ee.ria.taraauthserver.utils.OCSPValidator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.id-card.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class IdcardConfigurationDisabledTest extends DisabledConfigurationTest {
    @Test
    public void whenLegalPersonDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(IdCardController.class);
        assertBeanNotInitiated(OCSPValidator.class);
        assertBeanNotInitiated(OCSPConfigurationResolver.class);
    }
}
