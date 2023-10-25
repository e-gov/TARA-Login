package ee.ria.taraauthserver.authentication.veriff;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.springframework.http.HttpStatus;
import org.springframework.session.SessionRepository;
import org.springframework.session.Session;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import javax.cache.Cache;
import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_VERIFF_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_VERIFF;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_VERIFF_RESPONSE;
import static java.lang.String.format;
import static java.util.EnumSet.of;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.veriff.enabled")
public class VeriffCancelController {
    static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = of(INIT_VERIFF, POLL_VERIFF_STATUS, WAITING_VERIFF_RESPONSE, VERIFICATION_FAILED, VERIFICATION_COMPLETED);

    @Autowired
    StatisticsLogger statisticsLogger;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private Cache<String, String> veriffRelayStateCache;

    @PostMapping(value = "/auth/veriff/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    public RedirectView veriffPollCancel(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (taraSession.getState().equals(VERIFICATION_SUCCESS)) {
            String userCancelUri = taraSession.getLoginRequestInfo().getUserCancelUri();
            logAndInvalidateSession(taraSession);
            return new RedirectView(userCancelUri);
        } else if (!ALLOWED_STATES.contains(taraSession.getState())) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, format("Invalid authentication state: '%s', expected one of: %s", taraSession.getState(), ALLOWED_STATES));
        }

        taraSession.setState(VERIFICATION_CANCELED);
        log.warn("Veriff ID verification process has been canceled");
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge() + "&cancel_webauthn=true");
    }

    public void validateSession(Session session) {
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");

        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        SessionUtils.assertSessionInState(taraSession, WAITING_VERIFF_RESPONSE);
    }

    private void logAndInvalidateSession(TaraSession taraSession) {
      taraSession.setState(VERIFICATION_CANCELED);
      statisticsLogger.log(taraSession);
      SessionUtils.invalidateSession();
  }
}