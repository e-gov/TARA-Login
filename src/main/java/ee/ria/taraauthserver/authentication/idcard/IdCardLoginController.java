package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.authtoken.WebEidAuthToken;
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

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@RestController
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardLoginController {

    private final IdCardLoginService idCardLoginService;

    @PostMapping(path = "/auth/id/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> handleRequest(@RequestBody WebEidData data, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        logWebEidData(data);

        idCardLoginService.attemptLogin(data, taraSession);
        return ResponseEntity.ok(of("status", "COMPLETED"));
    }

    private void logWebEidData(WebEidData data) {
        WebEidAuthToken authToken = data.authToken;
        LogstashMarker marker = append("tara.webeid.extension_version", data.extensionVersion)
                .and(append("tara.webeid.native_app_version", data.nativeAppVersion))
                .and(append("tara.webeid.status_duration_ms", data.statusDurationMs))
                .and(append("tara.webeid.code", "SUCCESS"))
                .and(append("tara.webeid.auth_token.unverified_certificate", authToken.unverifiedCertificate()))
                .and(append("tara.webeid.auth_token.signature", authToken.signature()))
                .and(append("tara.webeid.auth_token.algorithm", authToken.algorithm()))
                .and(append("tara.webeid.auth_token.format", authToken.format()));
        log.info(marker, "Client-side Web eID operation successful");
    }

    @Data
    public static class WebEidData {
        private WebEidAuthToken authToken;
        private String extensionVersion;
        private String nativeAppVersion;
        private String statusDurationMs;
    }
}
