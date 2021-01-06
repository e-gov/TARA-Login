package ee.ria.taraauthserver.config;

import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.Session;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import javax.cache.Cache;
import java.time.Duration;
import java.util.function.Consumer;

import static ee.ria.taraauthserver.session.IgniteSessionRepository.DEFAULT_SESSION_MAP_NAME;
import static java.lang.Math.toIntExact;
import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.cache.expiry.CreatedExpiryPolicy.factoryOf;
import static org.apache.ignite.cache.CacheAtomicityMode.ATOMIC;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;

@Configuration
@EnableSpringHttpSession
public class SessionConfiguration {
    public static final String TARA_SESSION_COOKIE_NAME = "SESSION";

    @Bean
    public Ignite ignite(IgniteConfiguration cfg) {
        return Ignition.getOrStart(cfg);
    }

    @Bean
    @ConfigurationProperties(prefix = "ignite")
    public IgniteConfiguration igniteConfiguration(Consumer<IgniteConfiguration> configurer) {
        IgniteConfiguration cfg = new IgniteConfiguration();
        configurer.accept(cfg);
        return cfg;
    }

    @Bean
    public Consumer<IgniteConfiguration> nodeConfigurer() {
        return cfg -> { /* No-op. */ };
    }

    @Bean
    public Cache<String, Session> sessionCache(Ignite igniteInstance, @Value("${spring.session.timeout}") Duration sessionTimeout) {
        return igniteInstance.getOrCreateCache(new CacheConfiguration<String, Session>()
                .setName(DEFAULT_SESSION_MAP_NAME)
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setBackups(0)
                .setExpiryPolicyFactory(factoryOf(new javax.cache.expiry.Duration(SECONDS, sessionTimeout.toSeconds()))));
    }

    @Bean
    public CookieSerializer cookieSerializer(@Value("${spring.session.timeout}") Duration sessionTimeout) {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(toIntExact(sessionTimeout.toSeconds()));
        serializer.setUseSecureCookie(true);
        serializer.setSameSite("Strict");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseBase64Encoding(false);
        serializer.setCookieName(TARA_SESSION_COOKIE_NAME);
        return serializer;
    }
}
