package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.decorate.MapperBuilderDecorator;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.util.StdDateFormat;

public class LogbackMapperBuilderDecorator implements MapperBuilderDecorator<JsonMapper, JsonMapper.Builder> {

    @Override
    public JsonMapper.Builder decorate(JsonMapper.Builder builder) {
        builder.configure(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        builder.defaultDateFormat(new StdDateFormat().withColonInTimeZone(false));
        builder.changeDefaultPropertyInclusion(inclusion -> JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL));
        builder.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        return builder;
    }
}
