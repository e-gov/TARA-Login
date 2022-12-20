package ee.ria.taraauthserver.security;

import co.elastic.apm.api.ElasticApm;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.MDC;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.AuthInitController.AUTH_INIT_REQUEST_MAPPING;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
public class SessionManagementFilter extends OncePerRequestFilter {
    private static final RequestMatcher AUTH_INIT_REQUEST_MATCHER = new AntPathRequestMatcher(AUTH_INIT_REQUEST_MAPPING);
    private static final RequestMatcher AUTH_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/**");
    public static final String MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID = "labels.tara_trace_id";
    private static final String APM_LABEL_KEY_FLOW_TRACE_ID = "tara_trace_id";
    public static final String MDC_ATTRIBUTE_KEY_GOVSSO_FLOW_TRACE_ID = "labels.govsso_trace_id";
    private static final String APM_LABEL_KEY_GOVSSO_FLOW_TRACE_ID = "govsso_trace_id";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (AUTH_INIT_REQUEST_MATCHER.matches(request)) {
            session = createNewSession(request, session);
        }

        if (session != null && AUTH_REQUEST_MATCHER.matches(request)) {
            setFlowTraceId(session);
            setGovSsoFlowTraceId(session);
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID);
            MDC.remove(MDC_ATTRIBUTE_KEY_GOVSSO_FLOW_TRACE_ID);
        }

        SessionCreationRestrictingRequestWrapper wrappedRequest = new SessionCreationRestrictingRequestWrapper(request);
        filterChain.doFilter(wrappedRequest, response);
        // TODO: Could clear MDC in finally block, but tests fail while application itself behaves correctly, needs investigation.
    }

    private void setFlowTraceId(HttpSession session) {
        String taraTraceId = DigestUtils.sha256Hex(session.getId());
        ElasticApm.currentTransaction().setLabel(APM_LABEL_KEY_FLOW_TRACE_ID, taraTraceId);
        MDC.put(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, taraTraceId);
    }

    private void setGovSsoFlowTraceId(HttpSession session) {
        TaraSession taraSession = (TaraSession) requireNonNull(session.getAttribute(TARA_SESSION));
        if (taraSession.getGovSsoLoginRequestInfo() != null) {
            setGovSsoFlowTraceId(taraSession.getGovSsoLoginRequestInfo().getChallenge());
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_GOVSSO_FLOW_TRACE_ID);
        }
    }

    public static void setGovSsoFlowTraceId(@NonNull String govSsoLoginChallenge) {
        ElasticApm.currentTransaction().setLabel(APM_LABEL_KEY_GOVSSO_FLOW_TRACE_ID, govSsoLoginChallenge);
        MDC.put(MDC_ATTRIBUTE_KEY_GOVSSO_FLOW_TRACE_ID, govSsoLoginChallenge);
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

    @Slf4j
    private static class SessionCreationRestrictingRequestWrapper extends HttpServletRequestWrapper {

        public SessionCreationRestrictingRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public HttpSession getSession(boolean create) {
            HttpSession session = super.getSession(false);
            if (session != null) {
                return session;
            }
            if (!create) {
                return null;
            }
            throw new SessionCreationNotAllowedException();
        }

        @Override
        public HttpSession getSession() {
            return getSession(true);
        }

        @Override
        public String changeSessionId() {
            throw new SessionIdChangeNotAllowedException();
        }

    }

}
