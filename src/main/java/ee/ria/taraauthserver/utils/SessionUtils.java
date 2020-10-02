package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.session.AuthSession;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Slf4j
@UtilityClass
public class SessionUtils {

    public static AuthSession getOrCreateAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession();
        AuthSession authSession = (AuthSession) httpSession.getAttribute("session");
        return authSession != null? authSession : new AuthSession();
    }

    public static AuthSession getAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession(false);
        if (httpSession == null)
            throw new BadRequestException("Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
        else
            return (AuthSession) httpSession.getAttribute("session");
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
