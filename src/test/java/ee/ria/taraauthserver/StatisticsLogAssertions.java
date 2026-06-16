package ee.ria.taraauthserver;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.taraauthserver.logging.StatisticsLogger.SessionStatistics;
import net.logstash.logback.marker.LogstashMarker;
import org.slf4j.Marker;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

public class StatisticsLogAssertions {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static void assertFields(ILoggingEvent event, SessionStatistics expectedStatistics) {
        Map<String, String> actualFields = extractStatisticsFields(event);
        Map<String, String> expectedFields = statisticsToStringMap(expectedStatistics);
        for (Map.Entry<String, String> field : expectedFields.entrySet()) {
            assertThat("Field: " + field.getKey(), actualFields.get(field.getKey()), equalTo(field.getValue()));
        }
        Set<String> unexpectedKeys = new HashSet<>(actualFields.keySet());
        unexpectedKeys.removeAll(expectedFields.keySet());
        assertThat("Unexpected fields in actual statistics", unexpectedKeys, empty());
    }

    private static Map<String, String> extractStatisticsFields(ILoggingEvent event) {
        Marker marker = event.getMarker();
        if (!(marker instanceof LogstashMarker)) {
            throw new AssertionError("Expected LogstashMarker for statistics event but got: " + marker.getClass().getName());
        }
        return markerToStringMap((LogstashMarker) marker);
    }

    private static Map<String, String> statisticsToStringMap(SessionStatistics statistics) {
        Map<String, Object> jsonMap = OBJECT_MAPPER.convertValue(statistics, new TypeReference<>() {});
        return toStringMap(jsonMap);
    }

    private static Map<String, String> markerToStringMap(LogstashMarker marker) {
        try {
            StringWriter sw = new StringWriter();
            try (JsonGenerator gen = OBJECT_MAPPER.getFactory().createGenerator(sw)) {
                gen.writeStartObject();
                marker.writeTo(gen);
                gen.writeEndObject();
            }
            Map<String, Object> jsonMap = OBJECT_MAPPER.readValue(sw.toString(), new TypeReference<>() {});
            return toStringMap(jsonMap);
        } catch (IOException e) {
            throw new AssertionError("Failed to serialize statistics marker to JSON", e);
        }
    }

    private static Map<String, String> toStringMap(Map<String, Object> jsonMap) {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : jsonMap.entrySet()) {
            result.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
        return result;
    }

}
