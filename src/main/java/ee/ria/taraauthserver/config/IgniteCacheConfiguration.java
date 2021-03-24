package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AlertsConfigurationProperties.Alert;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.logger.slf4j.Slf4jLogger;
import org.apache.ignite.spi.discovery.tcp.TcpDiscoverySpi;
import org.apache.ignite.spi.discovery.tcp.ipfinder.vm.TcpDiscoveryVmIpFinder;
import org.apache.ignite.ssl.SslContextFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.Session;

import javax.cache.Cache;
import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.cache.expiry.CreatedExpiryPolicy.factoryOf;
import static org.apache.ignite.cache.CacheAtomicityMode.ATOMIC;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;

@Slf4j
@Configuration
public class IgniteCacheConfiguration {
    public static final String SESSION_CACHE_NAME = "spring:session:sessions";
    public static final String ALERTS_CACHE_NAME = "tara_alerts";
    public static final String EIDAS_RELAY_STATE_CACHE_NAME = "tara_eidas_relay_state";

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
        cfg.setGridLogger(new Slf4jLogger());
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
                .setName(SESSION_CACHE_NAME)
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setBackups(0)
                .setExpiryPolicyFactory(factoryOf(new javax.cache.expiry.Duration(SECONDS, sessionTimeout.toSeconds()))));
    }

    @Bean
    public Cache<String, String> eidasRelayStateCache(Ignite igniteInstance, @Value("${tara.auth-methods.eidas.relay_state_cache_duration_in_seconds:300}") Integer relayStateTimeout) {
        return igniteInstance.getOrCreateCache(new CacheConfiguration<String, String>()
                .setName(EIDAS_RELAY_STATE_CACHE_NAME)
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setExpiryPolicyFactory(factoryOf(new javax.cache.expiry.Duration(SECONDS, relayStateTimeout)))
                .setBackups(0));
    }

    @Bean
    public Cache<String, List<Alert>> alertsCache(Ignite igniteInstance, @Value("${tara.alerts.alerts_cache_duration_in_seconds:86400}") Integer alertsCacheTimeout) {
        return igniteInstance.getOrCreateCache(new CacheConfiguration<String, List<Alert>>()
                .setName(ALERTS_CACHE_NAME)
                .setCacheMode(PARTITIONED)
                .setAtomicityMode(ATOMIC)
                .setExpiryPolicyFactory(factoryOf(new javax.cache.expiry.Duration(SECONDS, alertsCacheTimeout)))
                .setBackups(0));
    }
}
