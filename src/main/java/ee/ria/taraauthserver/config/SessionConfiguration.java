package ee.ria.taraauthserver.config;

import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.spi.discovery.tcp.TcpDiscoverySpi;
import org.apache.ignite.spi.discovery.tcp.ipfinder.vm.TcpDiscoveryVmIpFinder;
import org.apache.ignite.ssl.SslContextFactory;
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
import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.cache.expiry.CreatedExpiryPolicy.factoryOf;
import static org.apache.ignite.cache.CacheAtomicityMode.ATOMIC;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;

/**
 * Replace {@link EnableSpringHttpSession} with Spring Session Ignite module or corresponding Community Extension,
 * that provides concurrency safe SessionRepository implementation backed by Ignite and configuration support when it becomes available.
 *
 * @see <a href="https://github.com/spring-projects/spring-session/pull/1730">Ignite integration module pull request</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.1/reference/html5/#httpsession">HttpSession Integration</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.2/reference/html5/#custom-sessionrepository">Remarks about concurrency</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.1/reference/html5/#community">Spring Session Community Extensions</a>
 */
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
        TcpDiscoverySpi tcpDiscoverySpi = new TcpDiscoverySpi();
        tcpDiscoverySpi.setIpFinder(new TcpDiscoveryVmIpFinder());
        cfg.setDiscoverySpi(tcpDiscoverySpi);
        cfg.setSslContextFactory(new SslContextFactory());
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
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookiePath("/");
        serializer.setUseSecureCookie(true);
        serializer.setSameSite("None");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseBase64Encoding(false);
        serializer.setCookieName(TARA_SESSION_COOKIE_NAME);
        return serializer;
    }
}
