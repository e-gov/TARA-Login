package ee.ria.taraauthserver.authentication.smartid.web2app;

import ee.ria.taraauthserver.authentication.smartid.SmartIdSessionStatus;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.SessionResetException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.CancelPollSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.utils.RequestUtils;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
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
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_WEB2APP;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;
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

    public static final String CALLBACK_VIEW = "sidWeb2AppCallback";

    @Autowired
    private AuthSidWeb2AppService authSidWeb2AppService;

    @Autowired
    StatisticsLogger statisticsLogger;

    @ResponseBody
    @PostMapping(value = "/auth/sid/web2app/init", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> authSidInit(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) throws URISyntaxException {
        log.info("Initiating Smart-ID Web2App authentication session");
        validateSession(taraSession, INIT_AUTH_PROCESS);
        URI deviceLink = authSidWeb2AppService.startSidAuthSession(taraSession);
        return Map.of("deviceLink", deviceLink.toString());
    }

    @ResponseBody
    @GetMapping(value = "/auth/sid/web2app/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> authSidPoll(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession,
                                           @RequestParam String sessionToken) {
        log.info("Validating Smart-ID Web2App poll endpoint");
        validateSessionNotReset(taraSession, sessionToken);
        validateSession(taraSession,
                INIT_SID_WEB2APP,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
                AUTHENTICATION_FAILED);
        switch (taraSession.getState()) {
            case AUTHENTICATION_FAILED:
                throw getExceptionForAuthenticationFailureOnPoll(taraSession);
            case POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED:
                return Map.of("status", "COMPLETED");
            // INIT_SID_WEB2APP or POLL_SID_WEB2APP_STATUS, depending on whether "/auth/sid/web2app/init" controller
            // has already updated the status or not
            default:
                return Map.of("status", "PENDING");
        }
    }

    @PostMapping(value = "/auth/sid/web2app/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authSidPollCancel(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Validating Smart-ID Web2App poll cancel endpoint");
        validateSession(taraSession,
                INIT_SID_WEB2APP,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
                AUTHENTICATION_FAILED);
        taraSession.accept(new CancelPollSmartIdWeb2AppAuthenticationSessionUpdate());
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
        log.warn("Smart ID authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge="
                + taraSession.getLoginRequestInfo().getChallenge() + RequestUtils.getLangParam(taraSession));
    }

    @GetMapping(value = "/auth/sid/web2app/callback", produces = MediaType.TEXT_HTML_VALUE)
    public String authSidCallback(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession,
                                  @RequestParam String value) {
        log.info("Validating Smart-ID Web2App callback endpoint");
        // An additional "pre-validation" check to show user nicer error messages
        validateAuthenticationNotCancelled(taraSession, value);
        validateSession(taraSession,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
                AUTHENTICATION_FAILED);
        return CALLBACK_VIEW;
    }

    @ResponseBody
    @GetMapping(value = "/auth/sid/web2app/callback/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> authSidCallbackPoll(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession,
                                           @RequestParam String value,
                                           @RequestParam String sessionSecretDigest,
                                           @RequestParam String userChallengeVerifier) {
        log.info("Validating Smart-ID Web2App callback poll endpoint");
        validateSession(taraSession,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
                AUTHENTICATION_FAILED);
        if (taraSession.getState() == POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED) {
            SessionStatus sessionStatus = taraSession.getSmartIdWeb2AppSession().getSessionStatus();
            if (!SmartIdSessionStatus.COMPLETE.equals(sessionStatus.getState())) {
                throw new IllegalStateException("Unexpected session status: " + sessionStatus.getState());
            }
            // Following line may transition state to AUTHENTICATION_FAILED. 
            // Meaning AUTHENTICATION_FAILED check has to be after this line.
            authSidWeb2AppService.handleFinalAuthenticationResult( 
                    taraSession, sessionStatus, userChallengeVerifier, sessionSecretDigest, value);
        }
        if (taraSession.getState() == AUTHENTICATION_FAILED) {
            throw getExceptionForAuthenticationFailureOnPoll(taraSession);
        }
        if (taraSession.getState() == POLL_SID_WEB2APP_STATUS) {
            return Map.of("status", "PENDING");
        }
        return Map.of("status", "COMPLETED");
    }

    @PostMapping(value = "/auth/sid/web2app/callback/poll/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView authSidCallbackPollCancel(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Validating Smart-ID Web2App callback poll cancel endpoint");
        validateSession(taraSession,
                AUTHENTICATION_SUCCESS,
                POLL_SID_WEB2APP_STATUS,
                POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED,
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

    private static void validateSessionNotReset(TaraSession taraSession, String sessionToken) {
        if (taraSession == null) {
            return;
        }
        if (taraSession.getSmartIdWeb2AppSession() == null
                || !sessionToken.equals(taraSession.getSmartIdWeb2AppSession().getSessionToken())) {
            throw new SessionResetException("Session was reset while polling");
        }
    }

    private static void validateAuthenticationNotCancelled(TaraSession taraSession, String value) {
        if (taraSession == null) {
            throw new BadRequestException(ErrorCode.SID_WEB2APP_CALLBACK_SESSION_NOT_FOUND, "Session not found on Web2App callback");
        }
        try {
            AuthSidWeb2AppService.assertCallbackUrlTokenMatchesInitialToken(taraSession, value);
        } catch (Exception e) {
            throw new BadRequestException(ErrorCode.SID_WEB2APP_CALLBACK_VALUE_MISMATCH, e.getMessage());
        }
    }

    private static RuntimeException getExceptionForAuthenticationFailureOnPoll(TaraSession taraSession) {
        ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
        if (errorCode.equals(ErrorCode.ERROR_GENERAL)) {
            return new IllegalStateException(errorCode.getMessage());
        }
        if (errorCode.equals(ErrorCode.SID_INTERNAL_ERROR)) {
            return new ServiceNotAvailableException(errorCode, "Sid Web2App poll failed", null);
        }
        return new BadRequestException(errorCode, "Sid Web2App poll failed");
    }

    private static void validateSession(TaraSession taraSession, TaraAuthenticationState... allowedStates) {
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
