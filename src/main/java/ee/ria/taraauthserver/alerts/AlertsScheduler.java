package ee.ria.taraauthserver.alerts;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.cache.Cache;
import java.time.LocalDate;
import java.util.List;

import static ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import static java.util.List.of;

@Slf4j
@Component
@ConditionalOnProperty(value = "tara.alerts.host-url")
public class AlertsScheduler {
    public static final String ALERTS_CACHE_KEY = "alertsCache";

    @Autowired
    private AlertsConfigurationProperties alertsConfigurationProperties;

    @Autowired
    private Cache<String, List<Alert>> alertsCache;

    @Autowired
    private RestTemplate alertsRestTemplate;

    @Scheduled(fixedRateString = "${tara.alerts.refresh-alerts-interval-in-milliseconds:600000}")
    public void updateAlertsTask() {
        try {
            String url = alertsConfigurationProperties.getHostUrl();
            log.info("requesting alerts from: " + alertsConfigurationProperties.getHostUrl());
            ResponseEntity<Alert[]> alerts = alertsRestTemplate.exchange(url, HttpMethod.GET, null, Alert[].class);
            alertsCache.put(ALERTS_CACHE_KEY, of(alerts.getBody()));
        } catch (Exception e) {
            log.error("Failed to update alerts - " + e.getMessage(), e);
        }
    }

    public String getFirstAlert(AuthenticationType authenticationType) {
        List<Alert> alerts = alertsCache.get(ALERTS_CACHE_KEY);
        return alerts == null ? null : alerts.stream()
                .filter(alert -> authenticationTypeHasValidAlert(alert, authenticationType))
                .findFirst()
                .map(alert -> alert.getLoginPageNotificationSettings().getNotificationText())
                .orElse(null);
    }

    private boolean authenticationTypeHasValidAlert(Alert alert, AuthenticationType authenticationType) {
        return alert.getLoginPageNotificationSettings().getAuthMethods().contains(authenticationType.getScope().getFormalName())
                && alert.getLoginPageNotificationSettings().isNotifyClientsOnTaraLoginPage()
                && alert.getStartTime().isBefore(LocalDate.now())
                && alert.getEndTime().isAfter(LocalDate.now());
    }
}
