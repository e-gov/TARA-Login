package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MutablePropertySources;

import java.util.AbstractMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
public class ActiveConfigurationLogger implements ApplicationListener<ApplicationStartedEvent> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private boolean configurationLogged = false;

    @SneakyThrows
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
                    .map(propertieName -> new AbstractMap.SimpleEntry<>(propertieName, environment.getProperty(propertieName)))
                    .collect(toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

            log.info(append("tara.conf.environment", objectMapper.writeValueAsString(new TreeMap<>(activeProperties)))
                    .and(append("tara.conf.active_profiles", asList(environment.getActiveProfiles()))), "Application active configuration");
            configurationLogged = true;
        }
    }
}
