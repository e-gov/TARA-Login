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
import java.util.List;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@UtilityClass
public class SessionUtils {

    public TaraSession getOrCreateAuthSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession();
        TaraSession taraSession = (TaraSession) httpSession.getAttribute(TARA_SESSION);
        return taraSession != null ? taraSession : new TaraSession();
    }

    public TaraSession getAuthSession() {
        HttpSession httpSession = getCurrentHttpSession();
        TaraSession taraSession = (TaraSession) httpSession.getAttribute(TARA_SESSION);
        if (taraSession != null) {
            return taraSession;
        } else {
            throw new BadRequestException(ErrorCode.SESSION_NOT_FOUND, String.format("The attribute '%s' was not found in session", TARA_SESSION));
        }
    }

    public TaraSession getAuthSessionInState(TaraAuthenticationState expectedState) {
        TaraSession taraSession = getAuthSession();
        assertSessionInState(taraSession, expectedState);
        return taraSession;
    }

    private HttpSession getCurrentHttpSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        HttpSession httpSession = request.getSession(false);

        if (httpSession != null) {
            return httpSession;
        } else {
            throw new BadRequestException(ErrorCode.SESSION_NOT_FOUND, "Session was not found");
        }
    }

    public void assertSessionInState(TaraSession taraSession, TaraAuthenticationState expectedState) {
        if (taraSession.getState() != expectedState) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected: '%s'", taraSession.getState(), expectedState));
        }
    }

    public void assertSessionInState(TaraSession taraSession, List<TaraAuthenticationState> expectedStates) {
        if (!expectedStates.contains(taraSession.getState()))
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s', expected one of: '%s'", taraSession.getState(), expectedStates));
    }

    public void assertSessionNotInState(TaraSession taraSession, TaraAuthenticationState forbiddenState) {
        if (taraSession.getState() == forbiddenState)
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, String.format("Invalid authentication state: '%s'", taraSession.getState()));
    }

    public void updateSession(TaraSession taraSession) {
        getCurrentHttpSession().setAttribute(TARA_SESSION, taraSession);
    }
}
