package ee.ria.taraauthserver.config;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MutablePropertySources;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
public class ActiveConfigurationLogger implements ApplicationListener<ApplicationStartedEvent> {
    private boolean configurationLogged = false;

    @Override
    public void onApplicationEvent(@NotNull ApplicationStartedEvent applicationPreparedEvent) {
        if (!configurationLogged) {
            ConfigurableEnvironment environment = applicationPreparedEvent.getApplicationContext().getEnvironment();
            MutablePropertySources propertySources = environment.getPropertySources();

            Set<String> propertieNames = propertySources.stream()
                    .filter(ps -> ps instanceof EnumerablePropertySource)
                    .map(p -> (EnumerablePropertySource<?>) p)
                    .flatMap(p -> stream(p.getPropertyNames()))
                    .collect(toSet());

            Map<String, Object> activeProperties = propertieNames.stream()
                    .map(propertieName -> new SimpleEntry<>(propertieName, environment.getProperty(propertieName)))
                    .collect(toMap(SimpleEntry::getKey, SimpleEntry::getValue));

            log.info(append("tara.conf", activeProperties), "Application active configuration with masked fields: {}", activeProperties.get("tara.masked_field_names"));
            configurationLogged = true;
        }
    }
}
