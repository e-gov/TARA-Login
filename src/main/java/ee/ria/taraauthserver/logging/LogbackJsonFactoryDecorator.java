package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import net.logstash.logback.decorate.JsonFactoryDecorator;

public class LogbackJsonFactoryDecorator implements JsonFactoryDecorator {

    @Override
    public JsonFactory decorate(JsonFactory factory) {
        ObjectMapper objectMapper = (ObjectMapper) factory.getCodec();
        objectMapper
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setDateFormat(new StdDateFormat().withColonInTimeZone(false))
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        return factory;
    }
}
