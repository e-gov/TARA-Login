package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.marker.LogstashMarker;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import static net.logstash.logback.marker.Markers.append;

public class ClientRequestLogger {
    private final org.slf4j.Logger log;
    public static final String PROP_URL_FULL = "url.full";
    public static final String PROP_REQUEST_METHOD = "http.request.method";
    public static final String PROP_REQUEST_BODY_CONTENT = "http.request.body.content";
    public static final String PROP_RESPONSE_BODY_CONTENT = "http.response.body.content";
    public static final String PROP_RESPONSE_STATUS_CODE = "http.response.status_code";
    private final String logRequestMessage;
    private final String logResponseMessage;
    private final ObjectMapper objectMapper;

    public enum Service {
        ALERTS,
        EIDAS,
        TARA_HYDRA,
        GOVSSO_HYDRA,
        OCSP,
        X_ROAD
    }

    public ClientRequestLogger(Service service, Class<?> classToBeLogged) {
        log = org.slf4j.LoggerFactory.getLogger(classToBeLogged);
        logRequestMessage = String.format("%s request", service.name());
        logResponseMessage = String.format("%s response: {}", service.name());
        objectMapper = JsonMapper
                .builder()
                .changeDefaultPropertyInclusion(inclusion -> JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .build();
    }

    public void logRequest(String requestUrl, HttpMethod httpMethod) {
        this.logRequest(requestUrl, httpMethod, null);
    }

    public void logRequest(String requestUrl, HttpMethod httpMethod, Object requestBodyObject) {
        LogstashMarker logMarker = append(PROP_REQUEST_METHOD, httpMethod.name())
                .and(append(PROP_URL_FULL, requestUrl));

        if (requestBodyObject != null) {
            try {
                String requestBodyJson = objectMapper.writeValueAsString(requestBodyObject);
                logMarker.and(append(PROP_REQUEST_BODY_CONTENT, requestBodyJson));
            } catch (JacksonException ex) {
                throw new IllegalStateException("Unable to convert request body object to JSON string", ex);
            }
        }
        log.info(logMarker, logRequestMessage);
    }

    public void logResponse(ResponseEntity<?> response) {
        logResponse(response.getStatusCode().value(), response.getBody());
    }

    public void logResponse(int httpStatusCode, Object responseBodyObject) {
        try {
            String responseBodyJson = objectMapper.writeValueAsString(responseBodyObject);
            logResponse(httpStatusCode, responseBodyJson);
        } catch (JacksonException ex) {
            throw new IllegalStateException("Unable to convert response body object to JSON string", ex);
        }
    }

    public void logResponse(int httpStatusCode) {
        logResponse(httpStatusCode, null);
    }

    public void logResponse(int httpStatusCode, String responseBodyObject) {
        LogstashMarker marker = append(PROP_RESPONSE_STATUS_CODE, httpStatusCode);
        if (responseBodyObject != null) {
            marker.and(append(PROP_RESPONSE_BODY_CONTENT, responseBodyObject));
        }
        log.info(marker, logResponseMessage, httpStatusCode);
    }
}
