package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NONCE_SENT;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@RequiredArgsConstructor
public class IdCardInitController {

    @NonNull
    private ChallengeNonceGenerator nonceGenerator;

    @PostMapping(value = "/auth/id/init", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> handleRequest(
            @RequestBody WebEidParameters webEidParameters, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        logWebEidParameters(webEidParameters);
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        initIdCardAuthentication(taraSession);
        String nonce = nonceGenerator.generateAndStoreNonce().getBase64EncodedNonce();
        taraSession.setState(NONCE_SENT);
        return ResponseEntity.ok(of("nonce", nonce));
    }

    private void logWebEidParameters(WebEidParameters params) {
        log.info("Web eID check results: code: {}, extensionversion: {}, nativeappversion: {}, errorstack: {}",
                value("webeid.code", params.code),
                value("webeid.extensionversion", params.extensionversion),
                value("webeid.nativeappversion", params.nativeappversion),
                value("webeid.errorstack", params.errorstack)
        );
    }

    private void initIdCardAuthentication(TaraSession taraSession) {
        IdCardAuthenticationResult authenticationResult = new IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    @Data
    private static class WebEidParameters {
        private String code;
        private String extensionversion;
        private String nativeappversion;
        private String errorstack;
        private String wait;
    }

}
