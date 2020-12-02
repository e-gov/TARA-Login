package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.legalperson.LegalpersonController;
import ee.ria.taraauthserver.authentication.legalperson.xroad.BusinessRegistryService;
import ee.ria.taraauthserver.health.ApplicationHealthController;
import ee.ria.taraauthserver.health.OidcServerHealthIndicator;
import ee.ria.taraauthserver.health.TruststoreHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.ws.rs.core.Application;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.health-endpoint.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class HealthEndpointDisabledTest extends DisabledConfigurationTest {

    @Test
    public void whenLegalPersonDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(ApplicationHealthConfiguration.class);
        assertBeanNotInitiated(ApplicationHealthController.class);
        assertBeanNotInitiated(OidcServerHealthIndicator.class);
        assertBeanNotInitiated(TruststoreHealthIndicator.class);
    }
}
