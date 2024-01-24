package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@UtilityClass
public class SessionUtils {

    public TaraSession getAuthSession() {
        HttpSession httpSession = getHttpSession();
        return httpSession == null ? null : (TaraSession) requireNonNull(httpSession.getAttribute(TARA_SESSION));
    }

    public HttpSession getHttpSession() {
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        ServletRequestAttributes attributes = (ServletRequestAttributes) requestAttributes;
        HttpServletRequest request = attributes.getRequest();
        return request.getSession(false);
    }

    public void assertSessionInState(TaraSession taraSession, EnumSet<TaraAuthenticationState> validSessionStates) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (!validSessionStates.contains(taraSession.getState())) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, format("Invalid authentication state: '%s', expected one of: %s", taraSession.getState(), validSessionStates));
        }
    }

    public void assertSessionInState(TaraSession taraSession, TaraAuthenticationState validSessionState) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        } else if (validSessionState != taraSession.getState()) {
            throw new BadRequestException(ErrorCode.SESSION_STATE_INVALID, format("Invalid authentication state: '%s', expected one of: [%s]", taraSession.getState(), validSessionState));
        }
    }

    public void invalidateSession() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.warn("Session has been invalidated: {}", value("tara.session.session_id", session.getId()));
        }
    }
}
