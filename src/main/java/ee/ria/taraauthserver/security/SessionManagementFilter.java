package ee.ria.taraauthserver.security;

import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.AuthInitController.AUTH_INIT_REQUEST_MAPPING;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
public class SessionManagementFilter extends OncePerRequestFilter {
    private static final RequestMatcher AUTH_INIT_REQUEST_MATCHER = new AntPathRequestMatcher(AUTH_INIT_REQUEST_MAPPING);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (AUTH_INIT_REQUEST_MATCHER.matches(request)) {
            createNewSession(request, session);
        }
        filterChain.doFilter(request, response);
    }

    private void createNewSession(HttpServletRequest request, HttpSession session) {
        if (session != null) {
            log.debug("Session '{}' has been invalidated", session.getId());
            session.invalidate();
        }
        session = request.getSession(true);
        TaraSession newTaraSession = new TaraSession(session.getId());
        session.setAttribute(TARA_SESSION, newTaraSession);
        log.debug("New session: {}", session.getId());
    }
}
