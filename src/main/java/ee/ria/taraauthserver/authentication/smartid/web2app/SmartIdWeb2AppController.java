package ee.ria.taraauthserver.authentication.smartid.web2app;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.CancelPollSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.utils.RequestUtils;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Map.of;

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

    public static final String CALLBACK_VIEW = "sidWeb2AppCallback";

    @Autowired
    private AuthSidWeb2AppService authSidWeb2AppService;

    @Autowired
    StatisticsLogger statisticsLogger;

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

    @GetMapping(value = "/auth/sid/web2app/callback", produces = MediaType.TEXT_HTML_VALUE)
    public String authSidCallback(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession,
            // TODO AUT-2450: Remove unused parameters from here
            @RequestParam String value,
            @RequestParam String sessionSecretDigest,
            @RequestParam String userChallengeVerifier) {
        log.info("Validating Smart-ID Web2App callback endpoint");
        validateSession(taraSession,
                POLL_SID_WEB2APP_STATUS,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                AUTHENTICATION_FAILED);
        authSidWeb2AppService.startPollingAuthenticationResult(taraSession, userChallengeVerifier);
        return CALLBACK_VIEW;
    }

    @ResponseBody
    @GetMapping(value = "/auth/sid/web2app/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> authSidPoll(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Validating Smart-ID Web2App poll endpoint");
        validateSession(taraSession,
                POLL_SID_WEB2APP_STATUS,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                AUTHENTICATION_FAILED);
        if (taraSession.getState() == NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            return of("status", "COMPLETED");
        } else if (taraSession.getState() == AUTHENTICATION_FAILED) {
            ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
            if (errorCode.equals(ErrorCode.ERROR_GENERAL)) {
                throw new IllegalStateException(errorCode.getMessage());
            } else if (errorCode.equals(ErrorCode.SID_INTERNAL_ERROR)) {
                throw new ServiceNotAvailableException(errorCode, "Sid Web2App poll failed", null);
            } else {
                throw new BadRequestException(taraSession.getAuthenticationResult().getErrorCode(), "Sid Web2App poll failed");
            }
        }
        return of("status", "PENDING");
    }

    @PostMapping(value = "/auth/sid/web2app/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authSidPollCancel(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        validateSession(taraSession,
                AUTHENTICATION_SUCCESS,
                POLL_SID_WEB2APP_STATUS,
                AUTHENTICATION_FAILED,
                NATURAL_PERSON_AUTHENTICATION_COMPLETED,
                LEGAL_PERSON_AUTHENTICATION_COMPLETED);
        if (taraSession.getState().equals(AUTHENTICATION_SUCCESS)) {
            String userCancelUri = taraSession.getLoginRequestInfo().getUserCancelUri();
            logAndInvalidateSession(taraSession);
            return new RedirectView(userCancelUri);
        }
        taraSession.accept(new CancelPollSmartIdWeb2AppAuthenticationSessionUpdate());
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
        log.warn("Smart ID authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge="
                + taraSession.getLoginRequestInfo().getChallenge() + RequestUtils.getLangParam(taraSession));
    }

    private void validateSession(TaraSession taraSession, TaraAuthenticationState... allowedStates) {
        SessionUtils.assertSessionInState(taraSession, Set.of(allowedStates));
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart-ID authentication method is not allowed");
        }
    }

    private void logAndInvalidateSession(TaraSession taraSession) {
        taraSession.setState(AUTHENTICATION_CANCELED);
        statisticsLogger.log(taraSession);
        SessionUtils.invalidateSession();
    }
}
