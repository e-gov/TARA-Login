package ee.ria.taraauthserver.config;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapAttributeConfig;
import com.hazelcast.config.MapIndexConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import lombok.extern.slf4j.Slf4j;
import nz.net.ultraq.thymeleaf.LayoutDialect;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.session.hazelcast.HazelcastIndexedSessionRepository;
import org.springframework.session.hazelcast.PrincipalNameExtractor;
import org.springframework.session.hazelcast.config.annotation.web.http.EnableHazelcastHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Locale;

import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@Configuration
@EnableHazelcastHttpSession
@ConfigurationPropertiesScan
public class TaraAuthServerConfiguration implements WebMvcConfigurer {
    public static final String TARA_SESSION_COOKIE_NAME = "SESSION";

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Bean
    public SSLContext trustContext() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return SSLContextBuilder
                .create().setKeyStoreType(authConfigurationProperties.getTls().getTrustStoreType())
                .loadTrustMaterial(
                        getFile(authConfigurationProperties.getTls().getTruststoreLocation()),
                        authConfigurationProperties.getTls().getTruststorePassword().toCharArray())
                .build();
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder, SSLContext sslContext) {
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();

        return builder
                .setConnectTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .setReadTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .build();
    }

    @Bean
    public HazelcastInstance hazelcastInstance() {
        Config config = new Config();
        MapAttributeConfig attributeConfig = new MapAttributeConfig()
                .setName(HazelcastIndexedSessionRepository.PRINCIPAL_NAME_ATTRIBUTE)
                .setExtractor(PrincipalNameExtractor.class.getName());
        config.getMapConfig(HazelcastIndexedSessionRepository.DEFAULT_SESSION_MAP_NAME)
                .addMapAttributeConfig(attributeConfig).addMapIndexConfig(
                new MapIndexConfig(HazelcastIndexedSessionRepository.PRINCIPAL_NAME_ATTRIBUTE, false));
        return Hazelcast.newHazelcastInstance(config);
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookiePath("/");
        serializer.setUseSecureCookie(true);
        serializer.setSameSite("Strict");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseBase64Encoding(false);
        serializer.setCookieName(TARA_SESSION_COOKIE_NAME);
        return serializer;
    }

    @Bean
    public LocalValidatorFactoryBean getValidator(MessageSource messageSource) {
        LocalValidatorFactoryBean bean = new LocalValidatorFactoryBean();
        bean.setValidationMessageSource(messageSource);
        return bean;
    }

    @Bean
    public LocaleResolver localeResolver(AuthConfigurationProperties configurationProperties) {
        SessionLocaleResolver bean = new SessionLocaleResolver();
        String locale = configurationProperties.getDefaultLocale();
        log.info("Setting default locale to [{}]", locale);
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
        log.info("calling locale change interceptor");
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
