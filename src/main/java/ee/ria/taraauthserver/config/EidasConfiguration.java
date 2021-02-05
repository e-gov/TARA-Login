package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import groovy.transform.AutoImplement;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;

@Slf4j
@Configuration
@EnableScheduling
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled", matchIfMissing = true)
public class EidasConfiguration {

    @Autowired
    EidasConfigurationProperties eidasConfigurationProperties;
    @Autowired
    RestTemplate restTemplate;

    @Scheduled(fixedRateString = "${tara.auth-methods.eidas.refresh-countries-interval}")
    public void scheduleFixedDelayTask() {
        log.info("starting fixed delay task");
        try {
            refreshCountriesList();
        } catch (Exception e) {
            log.error("Failed to update countries list - " + e.getMessage());
        }
    }

    private void refreshCountriesList() {
        String url = eidasConfigurationProperties.getClientUrl() + "/supportedCountries";
        log.info("requesting from: " + url);
        ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, null, Object.class);
        eidasConfigurationProperties.setCountries((ArrayList<String>) response.getBody());
        log.info("updated countries list to: " + response.getBody().toString());
    }

}