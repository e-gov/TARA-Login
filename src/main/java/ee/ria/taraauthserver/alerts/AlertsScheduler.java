package ee.ria.taraauthserver.alerts;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.Ignite;
import org.apache.ignite.binary.BinaryObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.cache.Cache;
import java.util.List;

import static ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

@Slf4j
@Component
@ConditionalOnProperty(value = "tara.alerts.enabled")
public class AlertsScheduler {
    public static final String ALERTS_CACHE_KEY = "alertsCache";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.ALERTS, this.getClass());

    @Autowired
    private AlertsConfigurationProperties alertsConfigurationProperties;

    @Autowired
    private Ignite ignite;

    @Autowired
    @Qualifier("alertsCache")
    private Cache<String, BinaryObject> alertsCache;

    @Autowired
    private RestTemplate alertsRestTemplate;

    @Scheduled(fixedRateString = "${tara.alerts.refresh-alerts-interval-in-milliseconds:600000}")
    public void updateAlertsTask() {
        try {
            String url = alertsConfigurationProperties.getHostUrl();

            requestLogger.logRequest(url, HttpMethod.GET);
            var response = alertsRestTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<List<Alert>>() {
                    });
            requestLogger.logResponse(response);

            BinaryObject binaryObject = ignite.binary().toBinary(new ApplicationAlerts(response.getBody()));
            alertsCache.put(ALERTS_CACHE_KEY, binaryObject);
        } catch (Exception e) {
            log.error("Failed to update alerts: ", e);
        }
    }

    public List<Alert> getActiveAlerts() {
        BinaryObject binaryObject = alertsCache.get(ALERTS_CACHE_KEY);
        if (binaryObject == null) {
            return emptyList();
        }
        ApplicationAlerts applicationAlerts = binaryObject.deserialize();
        return applicationAlerts.getAlerts().stream()
                .filter(Alert::isActive)
                .collect(toList());
    }

    @Data
    @AllArgsConstructor
    public static class ApplicationAlerts {
        private List<Alert> alerts;
    }
}
