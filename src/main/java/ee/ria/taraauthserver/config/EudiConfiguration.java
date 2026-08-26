package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.eudi.EudiploClient;
import ee.ria.taraauthserver.config.properties.EudiConfigurationProperties;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import javax.net.ssl.SSLContext;
import java.time.Clock;

@Configuration
@ConditionalOnProperty(value = "tara.auth-methods.eudi-wallet.enabled")
public class EudiConfiguration {

    @Bean
    public RestClient eudiploRestClient(RestClient.Builder builder,
                                        SSLContext trustContext,
                                        EudiConfigurationProperties eudiConfigurationProperties) {
        @SuppressWarnings("resource")
        HttpClient client = HttpClients.custom()
                .setConnectionManager(createConnectionManager(trustContext, eudiConfigurationProperties))
                .build();

        // HttpComponentsClientHttpRequestFactory no longer exposes connect-timeout configuration directly in Spring 7.
        // No RestTemplateErrorLogger: it logs every 4xx at ERROR, and several eudiplo 4xx answers are expected.
        return builder
                .requestFactory(new HttpComponentsClientHttpRequestFactory(client))
                .build();
    }

    @Bean
    public EudiploClient eudiploClient(@Qualifier("eudiploRestClient") RestClient eudiploRestClient,
                                       EudiConfigurationProperties eudiConfigurationProperties,
                                       Clock clock) {
        return new EudiploClient(eudiploRestClient, eudiConfigurationProperties, clock);
    }

    private static HttpClientConnectionManager createConnectionManager(SSLContext sslContext,
                                                                       EudiConfigurationProperties properties) {
        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(properties.getConnectionTimeoutMilliseconds()))
                .build();
        SocketConfig socketConfig = SocketConfig.custom()
                .setSoTimeout(Timeout.ofMilliseconds(properties.getReadTimeoutMilliseconds()))
                .build();

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setMaxConnPerRoute(properties.getMaxConnectionsTotal())
                .setMaxConnTotal(properties.getMaxConnectionsTotal())
                .setDefaultConnectionConfig(connectionConfig)
                .setDefaultSocketConfig(socketConfig)
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build())
                .build();
    }

}
