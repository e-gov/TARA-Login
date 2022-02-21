package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.time.Duration;

@Slf4j
@Configuration
@EnableScheduling
@ConditionalOnProperty(value = "tara.alerts.enabled")
public class AlertsConfiguration {

    @Bean
    public RestTemplate alertsRestTemplate(RestTemplateBuilder builder, SSLContext sslContext, AlertsConfigurationProperties alertsConfigurationProperties) {
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setMaxConnPerRoute(3)
                .setMaxConnTotal(3)
                .build();

        return builder
                .setConnectTimeout(Duration.ofSeconds(alertsConfigurationProperties.getConnectionTimeoutMilliseconds()))
                .setReadTimeout(Duration.ofSeconds(alertsConfigurationProperties.getReadTimeoutMilliseconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .errorHandler(new RestTemplateErrorLogger(Service.ALERTS))
                .build();
    }
}
