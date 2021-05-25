package ee.ria.taraauthserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import lombok.extern.slf4j.Slf4j;
import nz.net.ultraq.thymeleaf.LayoutDialect;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.resource.PathResourceResolver;

import javax.net.ssl.SSLContext;
import javax.validation.Validator;
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
    public SSLContext trustContext(AuthConfigurationProperties authConfigurationProperties) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return SSLContextBuilder
                .create().setKeyStoreType(authConfigurationProperties.getTls().getTrustStoreType())
                .loadTrustMaterial(
                        getFile(authConfigurationProperties.getTls().getTruststoreLocation()),
                        authConfigurationProperties.getTls().getTruststorePassword().toCharArray())
                .build();
    }

    @Bean
    public MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter(ObjectMapper objectMapper) {
        MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter(objectMapper);
        jsonConverter.setDefaultCharset(StandardCharsets.UTF_8);
        return jsonConverter;
    }

    @Bean
    @Primary
    public RestTemplate restTemplate(RestTemplateBuilder builder, SSLContext sslContext, AuthConfigurationProperties authConfigurationProperties) {
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setMaxConnPerRoute(authConfigurationProperties.getHydraService().getMaxConnectionsTotal())
                .setMaxConnTotal(authConfigurationProperties.getHydraService().getMaxConnectionsTotal())
                .build();

        List<HttpMessageConverter<?>> converters = new ArrayList<HttpMessageConverter<?>>();
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setSupportedMediaTypes(Collections.singletonList(MediaType.TEXT_HTML));
        converters.add(converter);

        return builder
                .additionalMessageConverters(converters)
                .setConnectTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .setReadTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
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
        String locale = configurationProperties.getDefaultLocale();
        log.info("Setting default locale to [{}]", value("tara.conf.default_locale", locale));
        bean.setCookieName("LOGIN_LOCALE");
        bean.setDefaultLocale(new Locale(locale));
        return bean;
    }

    @Bean
    public LayoutDialect layoutDialect() {
        return new LayoutDialect();
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
}
