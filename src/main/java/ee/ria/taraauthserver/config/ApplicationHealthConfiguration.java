package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.health.OidcServerHealthIndicator;
import ee.ria.taraauthserver.health.TruststoreHealthIndicator;
import org.springframework.boot.actuate.health.DefaultHealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@ConditionalOnProperty(value = "tara.health-endpoint.enabled", matchIfMissing = true)
public class ApplicationHealthConfiguration {

    @Bean
    public HealthContributorRegistry healthContributorRegistry(ApplicationContext ctx) {
        Map<String, HealthContributor> healthContributorMap = new HashMap<>();
        healthContributorMap.put("oidcServer", ctx.getBean(OidcServerHealthIndicator.class));
        healthContributorMap.put("truststore", ctx.getBean(TruststoreHealthIndicator.class));
        return new DefaultHealthContributorRegistry(new LinkedHashMap<>(healthContributorMap));
    }
}
