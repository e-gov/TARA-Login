package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_USER_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@RequiredArgsConstructor
public class IdCardErrorController {

    @PostMapping(value = "/auth/id/error", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> handleRequest(@RequestBody WebEidErrorParameters webEidErrorParameters,
                                                             @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }
        logWebEidError(webEidErrorParameters);

        // An exception is always thrown in this block. It is caught in class ErrorHandler, which sets the state of
        // the session to AUTHENTICATION_FAILED and writes the failure into the statistics log.
        switch (webEidErrorParameters.code) {
            case "ERR_WEBEID_EXTENSION_UNAVAILABLE":
            case "ERR_WEBEID_NATIVE_UNAVAILABLE":
            case "ERR_WEBEID_VERSION_MISMATCH":
                throw new BadRequestException(IDC_WEBEID_NOT_AVAILABLE, webEidErrorParameters.code);
            case "ERR_WEBEID_USER_TIMEOUT":
                throw new BadRequestException(IDC_WEBEID_USER_TIMEOUT, webEidErrorParameters.code);
            default:
                throw new BadRequestException(IDC_WEBEID_ERROR, webEidErrorParameters.code, new String[]{webEidErrorParameters.code});
        }
    }

    private void logWebEidError(WebEidErrorParameters params) {
        LogstashMarker marker = append("tara.webeid.extension_version", params.extensionVersion)
                .and(append("tara.webeid.native_app_version", params.nativeAppVersion))
                .and(append("tara.webeid.status_duration_ms", params.statusDurationMs))
                .and(append("tara.webeid.error_stack", params.errorStack));
        log.error(marker, "Client-side Web eID operation error: {}", value("tara.webeid.code", params.code));
    }

    @Data
    static class WebEidErrorParameters {
        private String code;
        private String extensionVersion;
        private String nativeAppVersion;
        private String errorStack;
        private String statusDurationMs;
    }

}
