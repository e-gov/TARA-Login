package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.util.List;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

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
            throw new BadRequestException(ErrorTranslationCodes.SESSION_NOT_FOUND, String.format("The attribute '%s' was not found in session", TARA_SESSION));
        }
    }

    public static TaraSession getAuthSessionInState(TaraAuthenticationState expectedState) {
        TaraSession taraSession = getAuthSession();
        assertSessionInState(taraSession, expectedState);
        return taraSession;
    }

    private static HttpSession getCurrentHttpSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession(false);

        if (httpSession != null) {
            return httpSession;
        } else {
            throw new BadRequestException(ErrorTranslationCodes.SESSION_NOT_FOUND, "Session was not found");
        }
    }

    public static void assertSessionInState(TaraSession taraSession, TaraAuthenticationState expectedState) {
        if (taraSession.getState() != expectedState) {
            throw new BadRequestException(ErrorTranslationCodes.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected: '%s'", taraSession.getState(), expectedState));
        }
    }

    public static void assertSessionInState(TaraSession taraSession, List<TaraAuthenticationState> expectedStates) {
        if (!expectedStates.contains(taraSession.getState()))
            throw new BadRequestException(ErrorTranslationCodes.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected one of: '%s'", taraSession.getState(), expectedStates));
    }

    public static void assertSessionNotInState(TaraSession taraSession, TaraAuthenticationState forbiddenState) {
        if (taraSession.getState() == forbiddenState)
            throw new BadRequestException(ErrorTranslationCodes.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s'", taraSession.getState()));
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
