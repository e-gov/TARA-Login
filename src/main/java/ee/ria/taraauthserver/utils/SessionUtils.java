package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static ee.ria.taraauthserver.utils.Constants.TARA_SESSION;

@Slf4j
@UtilityClass
public class SessionUtils {

    public static TaraSession getOrCreateAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession();
        TaraSession taraSession = (TaraSession) httpSession.getAttribute(TARA_SESSION);
        return taraSession != null ? taraSession : new TaraSession();
    }

    public static TaraSession getAuthSession() {
        HttpSession httpSession = getCurrentHttpSession();
        TaraSession taraSession = (TaraSession) httpSession.getAttribute(TARA_SESSION);
        if (taraSession != null) {
            return taraSession;
        } else {
            throw new BadRequestException(ErrorMessages.SESSION_NOT_FOUND, String.format("The attribute '%s' was not found in session", TARA_SESSION));
        }
    }

    private static HttpSession getCurrentHttpSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession(false);

        if (httpSession != null) {
            return httpSession;
        } else {
            throw new BadRequestException(ErrorMessages.SESSION_NOT_FOUND, "Session was not found");
        }
    }

    public static void assertSessionInState(TaraSession taraSession, TaraAuthenticationState expectedState) {
        if (taraSession.getState() != expectedState) {
            throw new BadRequestException(ErrorMessages.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected: '%s'", taraSession.getState(), expectedState));
        }
    }

    public static void updateSession(TaraSession taraSession) {
        getCurrentHttpSession().setAttribute(TARA_SESSION, taraSession);
    }

    public static HttpSession resetSessionIfExists(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
            log.warn("session has been reset");
        }

        session = request.getSession(true);

        return session;
    }
}
