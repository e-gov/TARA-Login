package ee.ria.taraauthserver.logging;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.apache.commons.lang3.ArrayUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.DefaultResponseErrorHandler;

import java.nio.charset.StandardCharsets;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.PROP_RESPONSE_BODY_CONTENT;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.PROP_RESPONSE_STATUS_CODE;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
public class RestTemplateErrorLogger extends DefaultResponseErrorHandler {
    private final String LOG_RESPONSE_MESSAGE;

    public RestTemplateErrorLogger(ClientRequestLogger.Service service) {
        LOG_RESPONSE_MESSAGE = String.format("%s response: {}", service.name());
    }

    @SneakyThrows
    @Override
    protected byte @NotNull [] getResponseBody(@NotNull ClientHttpResponse response) {
        byte[] responseBody = super.getResponseBody(response);
        int httpStatusCode = response.getRawStatusCode();

        LogstashMarker marker = append(PROP_RESPONSE_STATUS_CODE, httpStatusCode);
        if (!ArrayUtils.isEmpty(responseBody)) {
            marker.and(append(PROP_RESPONSE_BODY_CONTENT, new String(responseBody, StandardCharsets.UTF_8)));
        }
        log.error(marker, LOG_RESPONSE_MESSAGE, httpStatusCode);
        return responseBody;
    }
}
