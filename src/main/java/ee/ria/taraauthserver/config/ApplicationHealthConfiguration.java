package ee.ria.taraauthserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.DefaultHealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;

@Slf4j
@Configuration
@ConditionalOnExpression("'${management.endpoints.web.exposure.include}'.contains('heartbeat')")
public class ApplicationHealthConfiguration {

    @Bean
    @ConditionalOnExpression("!'${management.endpoints.web.exposure.include}'.contains('health')" +
            "or '${management.endpoints.web.exposure.exclude}'.contains('health')")
    public HealthContributorRegistry healthContributorRegistry(ApplicationContext ctx) {
        return new DefaultHealthContributorRegistry(new LinkedHashMap<>(ctx.getBeansOfType(HealthContributor.class)));
    }
}