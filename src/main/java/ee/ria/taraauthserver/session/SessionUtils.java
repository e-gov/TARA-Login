package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Arrays;

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

    public void invalidateSession() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.warn("Session '{}' has been invalidated", session.getId());
        }
    }
}
