package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
import java.util.Set;

import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Configuration
@EnableScheduling
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
public class EidasConfiguration {

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    @Qualifier("restTemplate")
    private RestTemplate restTemplate;

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
        log.info("Refreshing countries list from: {}", value("url.full", url));
        ResponseEntity<String[]> response = restTemplate.exchange(url, HttpMethod.GET, null, String[].class);
        Set<String> countries = Set.of(response.getBody());
        eidasConfigurationProperties.setAvailableCountries(countries);
        log.info("Updated countries list to: {}", value("tara.conf.auth-methods.eidas.available_countries", countries));
    }

    @Bean(value = "eidasRestTemplate")
    public RestTemplate eidasRestTemplate(RestTemplateBuilder builder, SSLContext sslContext, EidasConfigurationProperties eidasConfigurationProperties) {
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setMaxConnPerRoute(eidasConfigurationProperties.getMaxConnectionsTotal())
                .setMaxConnTotal(eidasConfigurationProperties.getMaxConnectionsTotal())
                .build();

        List<HttpMessageConverter<?>> converters = new ArrayList<HttpMessageConverter<?>>();
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(Collections.singletonList(MediaType.TEXT_HTML));
        converters.add(converter);

        return builder
                .additionalMessageConverters(converters)
                .setConnectTimeout(Duration.ofSeconds(eidasConfigurationProperties.getRequestTimeoutInSeconds()))
                .setReadTimeout(Duration.ofSeconds(eidasConfigurationProperties.getReadTimeoutInSeconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .build();
    }
}