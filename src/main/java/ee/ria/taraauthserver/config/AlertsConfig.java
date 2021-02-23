package ee.ria.taraauthserver.config;

import brave.sampler.Matchers;
import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.ignite.Ignite;
import org.apache.ignite.configuration.CacheConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

import javax.cache.Cache;
import javax.net.ssl.SSLContext;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static org.apache.ignite.cache.CacheAtomicityMode.ATOMIC;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;

@Slf4j
@Configuration
public class AlertsConfig {

    @Data
    @RequiredArgsConstructor
    public static class Alert implements Serializable {
        @JsonProperty("start_time")
        LocalDate startTime;
        @JsonProperty("end_time")
        LocalDate endTime;
        @JsonProperty("login_page_notification_settings")
        LoginPageNotificationSettings loginPageNotificationSettings;
    }

    @Data
    public static class LoginPageNotificationSettings {
        @JsonProperty("notify_clients_on_tara_login_page")
        boolean notifyClientsOnTaraLoginPage;
        @JsonProperty("notification_text")
        String notificationText;
        @JsonProperty("display_only_for_authmethods")
        List<String> authMethods;
    }

    @Bean
    public Cache<String, List<AlertsConfig.Alert>> alertsCache(Ignite igniteInstance) {
        return igniteInstance.getOrCreateCache(new CacheConfiguration<String, List<AlertsConfig.Alert>>()
                .setName("alertsCache")
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setBackups(0));
    }

    @Bean(value = "alertsRestTemplate")
    public RestTemplate alertsRestTemplate(RestTemplateBuilder builder, SSLContext sslContext, AlertsConfigurationProperties alertsConfigurationProperties) {
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setMaxConnPerRoute(50)
                .setMaxConnTotal(50)
                .build();

        return builder
                .setConnectTimeout(Duration.ofSeconds(alertsConfigurationProperties.getConnectionTimeoutMilliseconds()))
                .setReadTimeout(Duration.ofSeconds(alertsConfigurationProperties.getReadTimeoutMilliseconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .build();
    }

}
