package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Slf4j
@UtilityClass
public class SessionUtils {

    public static final String SESSION_ATTRIBUTE_AUTH_SESSION = "session";

    public static AuthSession getOrCreateAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession();
        AuthSession authSession = (AuthSession) httpSession.getAttribute(SESSION_ATTRIBUTE_AUTH_SESSION);
        return authSession != null? authSession : new AuthSession();
    }

    public static AuthSession getAuthSession() {
        HttpSession httpSession = getCurrentHttpSession();
        AuthSession authSession = (AuthSession) httpSession.getAttribute("session");
        if (authSession != null) {
            return authSession;
        } else {
            throw new BadRequestException(ErrorMessages.SESSION_NOT_FOUND, String.format("The attribute '%s' was not found in session", SESSION_ATTRIBUTE_AUTH_SESSION));
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

    public static void assertSessionInState(AuthSession authSession, AuthState expectedState) {
        if (authSession.getState() != expectedState) {
            throw new BadRequestException(ErrorMessages.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected: '%s'", authSession.getState(), expectedState));
        }
    }

    public static void updateSession(AuthSession authSession) {
        getCurrentHttpSession().setAttribute(SESSION_ATTRIBUTE_AUTH_SESSION, authSession);
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
