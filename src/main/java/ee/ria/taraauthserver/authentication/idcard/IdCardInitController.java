package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@RequiredArgsConstructor
public class IdCardInitController {
    private final ChallengeNonceGenerator nonceGenerator;

    @PostMapping(value = "/auth/id/init")
    public ResponseEntity<Map<String, String>> handleRequest(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        initIdCardAuthentication(taraSession);
        String nonce = nonceGenerator.generateAndStoreNonce().getBase64EncodedNonce();
        log.info("Generated nonce: {}", nonce);
        return ResponseEntity.ok(of("nonce", nonce));
    }

    private void initIdCardAuthentication(TaraSession taraSession) {
        IdCardAuthenticationResult authenticationResult = new IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        taraSession.setAuthenticationResult(authenticationResult);
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
    }

}
