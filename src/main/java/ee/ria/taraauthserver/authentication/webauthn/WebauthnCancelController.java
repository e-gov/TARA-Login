package ee.ria.taraauthserver.authentication.webauthn;

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
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_REGISTRATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_WEBAUTHN_RESPONSE;
import static java.lang.String.format;
import static java.util.EnumSet.of;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.webauthn.enabled")
public class WebauthnCancelController {
    public static final String WEBAUTHN_LOGIN_CANCEL_REQUEST_MAPPING = "/auth/webauthn/login_cancel";
    public static final String WEBAUTHN_REGISTRATION_CANCEL_REQUEST_MAPPING = "/auth/webauthn/registration_cancel";

    @Autowired
    StatisticsLogger statisticsLogger;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private Cache<String, String> webauthnRelayStateCache;

    @PostMapping(value = WEBAUTHN_LOGIN_CANCEL_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView webauthnLoginCancel(@RequestParam(name = "RelayState") String relayState) {
        log.info("Handling Webauthn authentication cancel for relay state: {}", value("tara.session.eidas.relay_state", relayState));
        if (!webauthnRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(webauthnRelayStateCache.getAndRemove(relayState));
        validateSession(session);

        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        taraSession.setState(WEBAUTHN_AUTHENTICATION_CANCELED);
        log.warn("Webauthn authentication process has been canceled");
        return new RedirectView("/auth/init?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge() + "&cancel_webauthn=true");
    }

    @PostMapping(value = WEBAUTHN_REGISTRATION_CANCEL_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView webauthnRegistrationCancel(@RequestParam(name = "RelayState") String relayState) {
        log.info("Handling Webauthn registration cancel for relay state: {}", value("tara.session.eidas.relay_state", relayState));
        if (!webauthnRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(webauthnRelayStateCache.getAndRemove(relayState));
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");

        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        taraSession.setState(WEBAUTHN_REGISTRATION_CANCELED);
        log.warn("Webauthn registration process has been canceled");
        String redirectUrl = taraSession.getLoginRequestInfo().getUserCancelUri();
        return new RedirectView(redirectUrl);
    }

    public void validateSession(Session session) {
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");

        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        SessionUtils.assertSessionInState(taraSession, WAITING_WEBAUTHN_RESPONSE);
        if (((TaraSession.WebauthnAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState() == null) {
            throw new BadRequestException(ERROR_GENERAL, "Relay state is missing from session.");
        }
    }
}
