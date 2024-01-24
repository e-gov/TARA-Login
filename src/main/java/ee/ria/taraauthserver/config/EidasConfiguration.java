package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Configuration
@EnableScheduling
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
public class EidasConfiguration {
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Scheduled(fixedRateString = "${tara.auth-methods.eidas.refresh-countries-interval-in-milliseconds:300000}")
    public void scheduleFixedDelayTask() {
        try {
            refreshCountriesList();
        } catch (Exception e) {
            log.error("Failed to update countries list: {}", e.getMessage());
        }
    }

    private void refreshCountriesList() {
        String url = eidasConfigurationProperties.getClientUrl() + "/supportedCountries";

        requestLogger.logRequest(url, HttpMethod.GET);
        var response = hydraRestTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<Map<SPType, List<String>>>() {
                });
        requestLogger.logResponse(response);

        Map<SPType, List<String>> countries = response.getBody();
        if (countries == null || countries.isEmpty()) {
            throw new IllegalStateException("EIDAS client responded with empty supported countries list");
        }
        Collections.sort(countries.get(SPType.PRIVATE));
        Collections.sort(countries.get(SPType.PUBLIC));
        eidasConfigurationProperties.setAvailableCountries(countries);
        log.info("Updated countries configuration to: {}", value("tara.conf.auth-methods.eidas.available_countries", countries));
    }

    @Bean
    public RestTemplate eidasRestTemplate(RestTemplateBuilder builder, SSLContext sslContext, EidasConfigurationProperties eidasConfigurationProperties) {
        @SuppressWarnings("resource")
        HttpClient client = HttpClients.custom()
                .setConnectionManager(createConnectionManager(sslContext, eidasConfigurationProperties))
                .build();

        List<HttpMessageConverter<?>> converters = new ArrayList<>();
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(Collections.singletonList(MediaType.TEXT_HTML));
        converters.add(converter);

        //The setReadTimeout() method of this builder is not usable because we are instantiating our own HttpComponentsClientHttpRequestFactory, which does not support it.
        return builder
                .additionalMessageConverters(converters)
                .setConnectTimeout(Duration.ofSeconds(eidasConfigurationProperties.getRequestTimeoutInSeconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .errorHandler(new RestTemplateErrorLogger(Service.EIDAS))
                .build();
    }

    private static HttpClientConnectionManager createConnectionManager(SSLContext sslContext, EidasConfigurationProperties eidasConfigurationProperties) {
        SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(Timeout.ofSeconds(eidasConfigurationProperties.getReadTimeoutInSeconds())).build();

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setMaxConnPerRoute(eidasConfigurationProperties.getMaxConnectionsTotal())
                .setMaxConnTotal(eidasConfigurationProperties.getMaxConnectionsTotal())
                .setDefaultSocketConfig(socketConfig)
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build())
                .build();
    }
}
