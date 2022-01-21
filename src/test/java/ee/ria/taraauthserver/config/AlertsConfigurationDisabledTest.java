package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.alerts.AlertsScheduler;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.alerts.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class AlertsConfigurationDisabledTest extends DisabledConfigurationTest {
    @Test
    @Tag(value = "ALERT_CONFIG")
    public void whenHeartbeatEndpointDisabledThenBeansNotLoaded() {
        assertBeanNotInitiated(AlertsScheduler.class);
        assertBeanNotInitiated(AlertsConfiguration.class);
    }
}
