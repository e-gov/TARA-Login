package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
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
        @SuppressWarnings("resource")
        HttpClient client = HttpClients.custom()
                .setConnectionManager(createConnectionManager(sslContext, alertsConfigurationProperties))
                .build();

        //The setReadTimeout() method of this builder is not usable because we are instantiating our own HttpComponentsClientHttpRequestFactory, which does not support it.
        return builder
                .setConnectTimeout(Duration.ofMillis(alertsConfigurationProperties.getConnectionTimeoutMilliseconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .errorHandler(new RestTemplateErrorLogger(Service.ALERTS))
                .build();
    }

    private static HttpClientConnectionManager createConnectionManager(SSLContext sslContext, AlertsConfigurationProperties alertsConfigurationProperties) {
        SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(Timeout.ofMilliseconds(alertsConfigurationProperties.getReadTimeoutMilliseconds())).build();

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setDefaultSocketConfig(socketConfig)
                .setMaxConnPerRoute(3)
                .setMaxConnTotal(3)
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build())
                .build();
    }
}
