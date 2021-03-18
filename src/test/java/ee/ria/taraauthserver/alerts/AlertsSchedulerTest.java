package ee.ria.taraauthserver.alerts;


import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.LoginAlert;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import javax.cache.Cache;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.alerts.AlertsScheduler.ALERTS_CACHE_KEY;
import static ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.*;
import static java.time.OffsetDateTime.parse;
import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.alerts.host-url=https://localhost:9877/alerts",
                "tara.alerts.refresh-alerts-interval-in-milliseconds=1000"})
public class AlertsSchedulerTest extends BaseTest {

    @Autowired
    private ThymeleafSupport thymeleafSupport;

    @Autowired
    private Cache<String, List<Alert>> alertsCache;

    @AfterEach
    public void afterEachTest() {
        alertsCache.clear();
    }

    @Test
    @Tag(value = "ALERTS_SCHEDULED_TASK")
    void alerts_active() {
        createAlertsStub("mock_responses/alerts/active-alerts-response.json", 200);
        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get(ALERTS_CACHE_KEY), Matchers.notNullValue());

        List<Alert> midAlerts = thymeleafSupport.getActiveAlerts().stream()
                .filter(a -> a.isValidFor(MOBILE_ID))
                .collect(toList());
        List<Alert> idCardAlerts = thymeleafSupport.getActiveAlerts().stream()
                .filter(a -> a.isValidFor(ID_CARD))
                .collect(toList());
        List<Alert> sidAlerts = thymeleafSupport.getActiveAlerts().stream()
                .filter(a -> a.isValidFor(SMART_ID))
                .collect(toList());

        assertThat(midAlerts, hasSize(1));
        assertThat(idCardAlerts, hasSize(1));
        assertThat(sidAlerts, hasSize(1));

        Alert midAlert = midAlerts.get(0);
        Alert idCardAlert = idCardAlerts.get(0);
        Alert sidAlert = sidAlerts.get(0);

        assertEquals(parse("2021-01-01T12:00:00Z"), midAlert.getStartTime());
        assertEquals(parse("2031-01-01T12:00:00Z"), midAlert.getEndTime());
        assertEquals("Alert 1 message et", midAlert.getAlertMessage("et"));
        assertEquals("Alert 1 message en", midAlert.getAlertMessage("en"));
        LoginAlert midLoginAlert = midAlert.getLoginAlert();
        assertTrue(midLoginAlert.isEnabled());
        assertThat(midLoginAlert.getAuthMethods(), contains("mid"));

        assertEquals(parse("2021-01-02T12:00:00Z"), idCardAlert.getStartTime());
        assertEquals(parse("2031-01-02T12:00:00Z"), idCardAlert.getEndTime());
        assertEquals("Alert 2 message et", idCardAlert.getAlertMessage("et"));
        assertEquals("Alert 2 message en", idCardAlert.getAlertMessage("en"));
        LoginAlert idCardLoginAlert = idCardAlert.getLoginAlert();
        assertTrue(idCardLoginAlert.isEnabled());
        assertThat(idCardLoginAlert.getAuthMethods(), contains("smartid", "idcard"));

        assertEquals(parse("2021-01-02T12:00:00Z"), sidAlert.getStartTime());
        assertEquals(parse("2031-01-02T12:00:00Z"), sidAlert.getEndTime());
        assertEquals("Alert 2 message et", sidAlert.getAlertMessage("et"));
        assertEquals("Alert 2 message en", sidAlert.getAlertMessage("en"));
        LoginAlert sidLoginAlert = sidAlert.getLoginAlert();
        assertTrue(sidLoginAlert.isEnabled());
        assertThat(sidLoginAlert.getAuthMethods(), contains("smartid", "idcard"));
    }

    @Test
    @Tag(value = "ALERTS_SCHEDULED_TASK")
    void alerts_not_active() {
        createAlertsStub("mock_responses/alerts/inactive-alerts-response.json", 200);
        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get(ALERTS_CACHE_KEY), Matchers.notNullValue());
        assertThat(thymeleafSupport.getActiveAlerts(), empty());
    }

    @Test
    @Tag(value = "ALERTS_SCHEDULED_TASK")
    void alerts_not_enabled() {
        createAlertsStub("mock_responses/alerts/disabled-alerts-response.json", 200);
        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get(ALERTS_CACHE_KEY), Matchers.notNullValue());
        assertThat(thymeleafSupport.getActiveAlerts(), empty());
    }

    public static void createAlertsStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/alerts"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }
}

