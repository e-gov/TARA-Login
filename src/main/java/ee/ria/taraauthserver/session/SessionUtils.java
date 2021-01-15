package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Arrays;

import static ee.ria.taraauthserver.config.SecurityConfiguration.TARA_SESSION_CSRF_TOKEN;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Arrays.stream;

@Slf4j
@UtilityClass
public class SessionUtils {

    public TaraSession getAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession();
        return httpSession == null ? null : (TaraSession) httpSession.getAttribute(TARA_SESSION);
    }

    public void assertSessionInState(TaraSession taraSession, TaraAuthenticationState... validSessionStates) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (stream(validSessionStates).noneMatch(s -> s == taraSession.getState())) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected one of: %s", taraSession.getState(), Arrays.toString(validSessionStates)));
        }
    }

    public HttpSession resetHttpSession() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.warn("Session '{}' has been reset", session.getId());
            session.invalidate();
        }

        session = request.getSession(true);
        return session;
    }

    public HttpSession resetHttpSession(TaraSession taraSession) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        DefaultCsrfToken csrfToken = (DefaultCsrfToken) session.getAttribute(TARA_SESSION_CSRF_TOKEN);
        if (session != null) {
            log.warn("Session '{}' has been reset", session.getId());
            session.invalidate();
        }

        session = request.getSession(true);
        session.setAttribute(TARA_SESSION_CSRF_TOKEN, csrfToken);
        TaraSession newTaraSession = new TaraSession(session.getId());
        newTaraSession.setState(taraSession.getState());
        newTaraSession.setLoginRequestInfo(taraSession.getLoginRequestInfo());
        newTaraSession.setAuthenticationResult(taraSession.getAuthenticationResult());
        newTaraSession.setSelectedLegalPerson(taraSession.getSelectedLegalPerson());
        newTaraSession.setAllowedAuthMethods(taraSession.getAllowedAuthMethods());
        newTaraSession.setConsentChallenge(taraSession.getConsentChallenge());
        newTaraSession.setLegalPersonList(taraSession.getLegalPersonList());
        session.setAttribute(TARA_SESSION, newTaraSession);
        return session;
    }
}
