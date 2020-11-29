package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.legalperson.LegalpersonController;
import ee.ria.taraauthserver.authentication.legalperson.xroad.BusinessRegistryService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;


@TestPropertySource(
        locations= "classpath:application.yml",
        properties = { "tara.legal-person-authentication.enabled=false" })
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class LegalPersonConfigurationDisabledTest extends DisabledConfigurationTest {

    @Test
    public void whenLegalPersonDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(LegalPersonConfiguration.class);
        assertBeanNotInitiated(LegalpersonController.class);
        assertBeanNotInitiated(BusinessRegistryService.class);
    }
}
