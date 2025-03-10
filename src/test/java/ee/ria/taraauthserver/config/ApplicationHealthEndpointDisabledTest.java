package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.health.ApplicationHealthEndpoint;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"management.endpoints.jmx.exposure.exclude=*",
                "management.endpoints.jmx.exposure.include=",
                "management.endpoints.web.exposure.exclude=*",
                "management.endpoints.web.exposure.include="})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class ApplicationHealthEndpointDisabledTest extends DisabledConfigurationTest {

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_ENDPOINT_CONF")
    public void whenHeartbeatEndpointDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(ApplicationHealthEndpoint.class);
        assertBeanNotInitiated(ApplicationHealthConfiguration.class);
    }
}
