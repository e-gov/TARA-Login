package ee.ria.taraauthserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import jakarta.validation.Validator;
import java.security.UnrecoverableKeyException;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
import org.apache.ignite.ssl.SSLContextWrapper;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static net.logstash.logback.argument.StructuredArguments.value;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@Configuration
@ConfigurationPropertiesScan
public class TaraAuthServerConfiguration implements WebMvcConfigurer {

    @Bean
    public SSLContext xRoadTrustContext(AuthConfigurationProperties authConfigurationProperties)
        throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
        return createXRoadSSLContext(authConfigurationProperties);
    }

    @Bean
    public SSLContext trustContext(AuthConfigurationProperties authConfigurationProperties)
        throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return createTrustSSLContext(authConfigurationProperties);
    }

    private SSLContext createXRoadSSLContext(AuthConfigurationProperties authConfigurationProperties)
        throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
        AuthConfigurationProperties.TlsConfigurationProperties tlsProperties = authConfigurationProperties.getTls();
        SSLContextBuilder sslContextBuilder = SSLContextBuilder.create().setKeyStoreType(tlsProperties.getXRoadStoreType());

        sslContextBuilder
            .loadKeyMaterial(
                getFile(tlsProperties.getXRoadKeystoreLocation()),
                tlsProperties.getXRoadKeystorePassword().toCharArray(),
                tlsProperties.getXRoadKeystorePassword().toCharArray()
            )
            .loadTrustMaterial(
                getFile(tlsProperties.getXRoadTruststoreLocation()),
                tlsProperties.getXRoadTruststorePassword().toCharArray()
            );
        return finalizeSSLContext(sslContextBuilder, tlsProperties);
    }

    private SSLContext createTrustSSLContext(AuthConfigurationProperties authConfigurationProperties)
        throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        AuthConfigurationProperties.TlsConfigurationProperties tlsProperties = authConfigurationProperties.getTls();
        SSLContextBuilder sslContextBuilder = SSLContextBuilder.create().setKeyStoreType(tlsProperties.getTrustStoreType());

        sslContextBuilder.loadTrustMaterial(
            getFile(tlsProperties.getTruststoreLocation()),
            tlsProperties.getTruststorePassword().toCharArray()
        );

        return finalizeSSLContext(sslContextBuilder, tlsProperties);
    }

    private SSLContext finalizeSSLContext(SSLContextBuilder sslContextBuilder, AuthConfigurationProperties.TlsConfigurationProperties tlsProperties)
        throws NoSuchAlgorithmException, KeyManagementException {
        Optional.ofNullable(tlsProperties.getDefaultProtocol())
            .filter(StringUtils::isNotBlank)
            .ifPresent(sslContextBuilder::setProtocol);

        SSLContext sslContext = sslContextBuilder.build();

        boolean hasProtocols = !CollectionUtils.isEmpty(tlsProperties.getEnabledProtocols());
        boolean hasCipherSuites = !CollectionUtils.isEmpty(tlsProperties.getEnabledCipherSuites());

        if (hasProtocols || hasCipherSuites) {
            SSLParameters sslParameters = new SSLParameters();
            if (hasProtocols) {
                sslParameters.setProtocols(tlsProperties.getEnabledProtocols().toArray(new String[0]));
            }
            if (hasCipherSuites) {
                sslParameters.setCipherSuites(tlsProperties.getEnabledCipherSuites().toArray(new String[0]));
            }
            return new SSLContextWrapper(sslContext, sslParameters);
        }

        return sslContext;
    }

    @Bean
    public MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter(ObjectMapper objectMapper) {
        MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter(objectMapper);
        jsonConverter.setDefaultCharset(StandardCharsets.UTF_8);
        return jsonConverter;
    }

    @Bean
    public RestTemplate hydraRestTemplate(RestTemplateBuilder builder, SSLContext trustContext, AuthConfigurationProperties authConfigurationProperties) {
        @SuppressWarnings("resource")
        HttpClient client = HttpClients.custom()
                .setConnectionManager(createConnectionManager(trustContext, authConfigurationProperties))
                .build();

        List<HttpMessageConverter<?>> converters = new ArrayList<>();
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(Collections.singletonList(MediaType.TEXT_HTML));
        converters.add(converter);

        //The setReadTimeout() method of this builder is not usable because we are instantiating our own HttpComponentsClientHttpRequestFactory, which does not support it.
        return builder
                .additionalMessageConverters(converters)
                .setConnectTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .errorHandler(new RestTemplateErrorLogger(Service.TARA_HYDRA))
                .build();
    }

    @Bean
    public Validator defaultValidator(MessageSource messageSource) {
        LocalValidatorFactoryBean bean = new LocalValidatorFactoryBean();
        bean.setValidationMessageSource(messageSource);
        return bean;
    }

    @Bean
    public LocaleResolver localeResolver(AuthConfigurationProperties configurationProperties) {
        CookieLocaleResolver bean = new CookieLocaleResolver();
        String locale = AuthConfigurationProperties.DEFAULT_LOCALE;
        log.info("Setting default locale to [{}]", value("tara.conf.default_locale", locale));
        bean.setCookieName("__Host-LOCALE");
        //TODO AUT-1564 after spring boot migration to 3.x add bean.setCookieSameSite("Lax");
        bean.setCookieSecure(true);
        bean.setCookieMaxAge(365 * 24 * 60 * 60);

        // Setting default locale prevents CookieLocaleResolver from falling back to request.getLocale()
        bean.setDefaultLocale(new Locale(locale));
        return bean;
    }

    @Bean
    public ThymeleafSupport thymeleafSupport() {
        return new ThymeleafSupport();
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        log.info("Calling locale change interceptor");
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }

    private static HttpClientConnectionManager createConnectionManager(SSLContext sslContext, AuthConfigurationProperties authConfigurationProperties) {
        SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(Timeout.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds())).build();

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setMaxConnPerRoute(authConfigurationProperties.getHydraService().getMaxConnectionsTotal())
                .setMaxConnTotal(authConfigurationProperties.getHydraService().getMaxConnectionsTotal())
                .setDefaultSocketConfig(socketConfig)
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build())
                .build();
    }
}
