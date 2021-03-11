package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.ignite.Ignite;
import org.apache.ignite.configuration.CacheConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestTemplate;

import javax.cache.Cache;
import javax.cache.expiry.CreatedExpiryPolicy;
import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.apache.ignite.cache.CacheAtomicityMode.ATOMIC;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;

@Slf4j
@Configuration
@EnableScheduling
@ConditionalOnProperty(value = "tara.alerts.host-url")
public class AlertsConfig {

    @Bean
    public Cache<String, List<AlertsConfigurationProperties.Alert>> alertsCache(Ignite igniteInstance, AlertsConfigurationProperties alertsConfigurationProperties) {
        return igniteInstance.getOrCreateCache(new CacheConfiguration<String, List<AlertsConfigurationProperties.Alert>>()
                .setName("alertsCache")
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setExpiryPolicyFactory(CreatedExpiryPolicy.factoryOf(getDuration(alertsConfigurationProperties)))
                .setBackups(0));
    }

    private javax.cache.expiry.Duration getDuration(AlertsConfigurationProperties alertsConfigurationProperties) {
        return new javax.cache.expiry.Duration(TimeUnit.SECONDS, alertsConfigurationProperties.getAlertsCacheDurationInSeconds());
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
