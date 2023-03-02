package ee.ria.taraauthserver.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;

/**
 * Based on {@link org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository} but will never create a
 * session.
 * <p>
 * Since we do not want to start a {@link HttpSession} implicitly as it should only be started from
 * {@link SessionManagementFilter}, we will skip saving the generated CSRF token when a session has not been started.
 */
@Slf4j
public class NoSessionCreatingHttpSessionCsrfTokenRepository implements CsrfTokenRepository {

    public static final String CSRF_TOKEN_ATTR_NAME = "tara.csrf";
    public static final String CSRF_HEADER_NAME = "X-CSRF-TOKEN";
    public static final String CSRF_PARAMETER_NAME = "_csrf";

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (token == null) {
            if (session != null) {
                session.removeAttribute(CSRF_TOKEN_ATTR_NAME);
            }
        }
        else {
            if (session != null) {
                session.setAttribute(CSRF_TOKEN_ATTR_NAME, token);
            } else {
                /* Difference from HttpSessionCsrfTokenRepository, session creation is disabled here.
                 * Rest of the class has same logic as HttpSessionCsrfTokenRepository.
                 */
                log.debug("Not saving CSRF token, session not created");
            }
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (CsrfToken) session.getAttribute(CSRF_TOKEN_ATTR_NAME);
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, createNewToken());
    }

    private String createNewToken() {
        return UUID.randomUUID().toString();
    }

}
