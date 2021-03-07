package ee.ria.taraauthserver.utils;


import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.AlertsConfig;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.cache.Cache;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Slf4j
public class AlertsTest extends BaseTest {

    @Autowired
    ThymeleafSupport thymeleafSupport;

    @Autowired
    private Cache<String, List<AlertsConfig.Alert>> alertsCache;

    @Test
    void alerts_test() {
        createAlertsStub("mock_responses/alerts/alerts-response.json", 200);

        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get("alertsCache"), Matchers.notNullValue());

        String alertMessage = thymeleafSupport.getAlertIfAvailable(AuthenticationType.ID_CARD);
        String alertMessage2 = thymeleafSupport.getAlertIfAvailable(AuthenticationType.MOBILE_ID);
        assertEquals("Seoses SK plaaniliste hooldustöödega on ID kaardi teenuste kasutamine häiritud vahemikus 12.01.2020 00:00 kuni 13.01.2020 01:00", alertMessage);
        assertNull(alertMessage2);
    }

    @Test
    void alerts_idcard_alert_expired() {
        createAlertsStub("mock_responses/alerts/alerts-response-expired-alert.json", 200);

        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get("alertsCache"), Matchers.notNullValue());

        String alertMessage = thymeleafSupport.getAlertIfAvailable(AuthenticationType.ID_CARD);
        String alertMessage2 = thymeleafSupport.getAlertIfAvailable(AuthenticationType.MOBILE_ID);
        assertNull(alertMessage);
        assertEquals("Seoses SK plaaniliste hooldustöödega on Mobiil-ID teenuste kasutamine häiritud vahemikus 12.01.2020 00:00 kuni 13.01.2020 01:00", alertMessage2);
    }

    @Test
    void alerts_idcard_alert_not_yet_valid() {
        createAlertsStub("mock_responses/alerts/alerts-response-not-yet-valid-alert.json", 200);

        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get("alertsCache"), Matchers.notNullValue());

        String alertMessage = thymeleafSupport.getAlertIfAvailable(AuthenticationType.ID_CARD);
        assertNull(alertMessage);
    }

    @Test
    void alerts_idcard_notify_clients_on_login_page_is_false() {
        createAlertsStub("mock_responses/alerts/alerts-response-notify-is-false-alert.json", 200);

        await().atMost(FIVE_SECONDS)
                .until(() -> alertsCache.get("alertsCache"), Matchers.notNullValue());

        String alertMessage = thymeleafSupport.getAlertIfAvailable(AuthenticationType.ID_CARD);
        assertNull(alertMessage);
    }

    public static void createAlertsStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/alerts"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }
}
