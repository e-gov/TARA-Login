package ee.ria.taraauthserver.config;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapAttributeConfig;
import com.hazelcast.config.MapIndexConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import ee.ria.taraauthserver.utils.ThymeleafSupport;
import ee.sk.mid.MidClient;
import ee.sk.mid.rest.MidLoggingFilter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import nz.net.ultraq.thymeleaf.LayoutDialect;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Locale;

@Slf4j
@Configuration
@EnableHazelcastHttpSession
@ComponentScan(basePackages = {"ee.ria.taraauthserver"})
@EnableConfigurationProperties(AuthConfigurationProperties.class)
public class EidasAuthConfiguration implements WebMvcConfigurer {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return new RestTemplateBuilder()
                .setConnectTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
                .setReadTimeout(Duration.ofSeconds(authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds()))
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
        serializer.setCookieName("SESSION");
        return serializer;
    }

    @Bean
    public KeyStore midTrustStore(AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties, ResourceLoader loader) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Resource resource = loader.getResource(midAuthConfigurationProperties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(midAuthConfigurationProperties.getTruststoreType());
        trustStore.load(resource.getInputStream(), midAuthConfigurationProperties.getTruststorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    public MidClient midClient(KeyStore midTrustStore, AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties) {

        return MidClient.newBuilder()
                .withHostUrl(midAuthConfigurationProperties.getHostUrl())
                .withRelyingPartyUUID(midAuthConfigurationProperties.getRelyingPartyUuid())
                .withRelyingPartyName(midAuthConfigurationProperties.getRelyingPartyName())
                .withTrustSslContext(SSLContext.getDefault())
                .withNetworkConnectionConfig(clientConfig(midAuthConfigurationProperties))
                .withLongPollingTimeoutSeconds(30)
                .build();
    }

    private ClientConfig clientConfig(AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties) {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, midAuthConfigurationProperties.getConnectionTimeoutMilliseconds());
        clientConfig.property(ClientProperties.READ_TIMEOUT, midAuthConfigurationProperties.getReadTimeoutMilliseconds());
        clientConfig.register(new MidLoggingFilter());
        return clientConfig;
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
