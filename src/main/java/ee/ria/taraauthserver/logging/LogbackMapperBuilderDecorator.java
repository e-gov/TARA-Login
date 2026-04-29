package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.decorate.MapperBuilderDecorator;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.util.StdDateFormat;

@SuppressWarnings({"rawtypes", "unchecked"})
public class LogbackMapperBuilderDecorator implements MapperBuilderDecorator {

    @Override
    public Object decorate(Object decoratable) {
        MapperBuilder builder = (MapperBuilder) decoratable;
        builder.configure(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        builder.defaultDateFormat(new StdDateFormat().withColonInTimeZone(false));
        builder.changeDefaultPropertyInclusion(inclusion -> JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL));
        builder.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        return builder;
    }
}
