package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_INCIDENT_NR;
import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_REPORTABLE;
import static ee.ria.taraauthserver.error.ErrorAttributes.notReportableErrors;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_WEBEID_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.security.RequestCorrelationFilter.MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@RequiredArgsConstructor
public class IdCardErrorController {

    @NonNull
    private final MessageSource messageSource;
    private final List<String> WEB_EID_NOT_AVAILABLE_ERRORS = List.of(
            "ERR_WEBEID_EXTENSION_UNAVAILABLE",
            "ERR_WEBEID_NATIVE_UNAVAILABLE",
            "ERR_WEBEID_VERSION_MISMATCH");

    @PostMapping(value = "/auth/id/error", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> handleRequest(@RequestBody WebEidErrorParameters webEidErrorParameters,
                                                             @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }
        logWebEidError(webEidErrorParameters);
        taraSession.setState(AUTHENTICATION_FAILED);

        ErrorCode error;
        if (WEB_EID_NOT_AVAILABLE_ERRORS.contains(webEidErrorParameters.code)) {
            error = IDC_WEBEID_NOT_AVAILABLE;
        } else {
            error = IDC_WEBEID_ERROR;
        }
        String errorMessage = messageSource.getMessage(error.getMessage(), new String[]{webEidErrorParameters.code}, LocaleContextHolder.getLocale());
        return ResponseEntity.ok(of(
                "message", errorMessage,
                ERROR_ATTR_INCIDENT_NR, MDC.get(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID),
                ERROR_ATTR_REPORTABLE, !notReportableErrors.contains(error)));
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
