package ee.ria.taraauthserver.security;

import co.elastic.apm.api.ElasticApm;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.AuthInitController.AUTH_INIT_REQUEST_MAPPING;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class SessionManagementFilter extends OncePerRequestFilter {
    private static final RequestMatcher AUTH_INIT_REQUEST_MATCHER = new AntPathRequestMatcher(AUTH_INIT_REQUEST_MAPPING);
    private static final RequestMatcher AUTH_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/**");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getServletPath().startsWith("/auth/eidas/callback")) {
            request.setAttribute("SHOULD_NOT_FILTER" + CsrfFilter.class.getName(), Boolean.TRUE);
        }

        HttpSession session = request.getSession(false);
        if (AUTH_INIT_REQUEST_MATCHER.matches(request)) {
            session = createNewSession(request, session);
        }
        if (session != null && AUTH_REQUEST_MATCHER.matches(request)) {
            correlateApmWithLogs(session);
        }
        filterChain.doFilter(request, response);
    }

    private void correlateApmWithLogs(HttpSession session) {
        String taraTraceId = DigestUtils.sha256Hex(session.getId());
        ElasticApm.currentTransaction().setLabel("tara_trace_id", taraTraceId);
        MDC.put("labels.tara_trace_id", taraTraceId);
    }

    private HttpSession createNewSession(HttpServletRequest request, HttpSession session) {
        if (session != null) {
            log.info("Session has been invalidated: {}", value("tara.session.session_id", session.getId()));
            session.invalidate();
        }
        session = request.getSession(true);
        TaraSession newTaraSession = new TaraSession(session.getId());
        session.setAttribute(TARA_SESSION, newTaraSession);
        log.debug(append("tara.session.session_id", session.getId()), "New session created");
        return session;
    }
}
