package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

import javax.cache.Cache;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@EnableScheduling
public class AlertsScheduler {

    @Autowired
    AlertsConfigurationProperties alertsConfigurationProperties;

    @Autowired
    private Cache<String, List<AlertsConfig.Alert>> alertsCache;

    @Autowired
    @Qualifier("alertsRestTemplate")
    private RestTemplate alertsRestTemplate;

    @Scheduled(fixedRateString = "${tara.alerts.refresh-alerts-interval-in-milliseconds}")
    public void scheduleFixedDelayTask() {
        try {
            String url = alertsConfigurationProperties.getHostUrl();
            log.info("requesting alerts from: " + alertsConfigurationProperties.getHostUrl());
            ResponseEntity<AlertsConfig.Alert[]> response = alertsRestTemplate.exchange(url, HttpMethod.GET, null, AlertsConfig.Alert[].class);
            AlertsConfig.Alert[] alerts = response.getBody();
            alertsCache.put("alertsCache", Arrays.asList(alerts));
        } catch (Exception e) {
            log.error("Failed to update alerts - " + e.getMessage());
        }
    }

}
