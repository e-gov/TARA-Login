package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.idcard.IdCardInitController;
import ee.ria.taraauthserver.authentication.idcard.IdCardLoginController;
import ee.ria.taraauthserver.authentication.idcard.OCSPConfigurationResolver;
import ee.ria.taraauthserver.authentication.idcard.OCSPValidator;
import org.junit.jupiter.api.Tag;
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
    @Tag(value = "ESTEID_AUTH_ENABLED")
    public void whenLegalPersonDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(IdCardInitController.class);
        assertBeanNotInitiated(IdCardLoginController.class);
        assertBeanNotInitiated(OCSPValidator.class);
        assertBeanNotInitiated(OCSPConfigurationResolver.class);
    }
}
