package ee.ria.taraauthserver.authentication.smartid.web2app;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.web2app.enabled"
        },
        havingValue = "true"
)
public class SmartIdWeb2AppController {

    @Autowired
    private AuthSidWeb2AppService authSidWeb2AppService;

    @GetMapping(value = "/auth/sid/web2app/init", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Object> authSidInit(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) throws URISyntaxException {
        log.info("Initiating Smart-ID Web2App authentication session");
        validateSession(taraSession, INIT_AUTH_PROCESS);
        URI deviceLink = authSidWeb2AppService.startSidAuthSession(taraSession);
        return ResponseEntity
                .status(HttpStatus.SEE_OTHER.value())
                .header(HttpHeaders.LOCATION, deviceLink.toString())
                .build();
    }

    // TODO AUT-2504: Most of this logic needs to be moved into a new controller,
    //  which is polled from the frontend. This method should just receive the
    //  callback request and direct user to the frontend page used for polling.
    @GetMapping(value = "/auth/sid/web2app/callback", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Object> authSidCallback(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession,
            // TODO AUT-2450: Remove unused parameters from here
            @RequestParam String value,
            @RequestParam String sessionSecretDigest,
            @RequestParam String userChallengeVerifier) {
        log.info("Validating Smart-ID Web2App callback");
        validateSession(taraSession,
                POLL_SID_WEB2APP_STATUS,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                AUTHENTICATION_FAILED);
        TaraAuthenticationState result = authSidWeb2AppService.getAuthenticationResult(taraSession, userChallengeVerifier);

        if (result == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            // TODO AUT-2504: This redirection request needs to be done from frontend side,
            //  because /auth/accept only works with POST method.
            return ResponseEntity
                .status(HttpStatus.SEE_OTHER.value())
                .header(HttpHeaders.LOCATION, "/auth/accept")
                .build();
        } else if (result == AUTHENTICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL))
                throw new IllegalStateException(errorCode.getMessage());
            else if (errorCode.equals(ErrorCode.SID_INTERNAL_ERROR))
                throw new ServiceNotAvailableException(errorCode, "Sid poll failed", null);
            else
                throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Sid poll failed");
        }
        // TODO AUT-2504: This code should currently be unreachable, but will be
        //  used when polling will be implemented in the frontend.
        return ResponseEntity.ok(Collections.singletonMap("status", "PENDING"));
    }

    public void validateSession(TaraSession taraSession, TaraAuthenticationState... allowedStates) {
        SessionUtils.assertSessionInState(taraSession, Set.of(allowedStates));
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart-ID authentication method is not allowed");
        }
    }
}
