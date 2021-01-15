package ee.ria.taraauthserver.security;

import ee.ria.taraauthserver.session.TaraSession;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static ee.ria.taraauthserver.config.SessionConfiguration.TARA_SESSION_COOKIE_NAME;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Arrays.stream;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Component
@RequiredArgsConstructor
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_NAME_SESSION_ID = "sessionId";
    public static final String MDC_ATTRIBUTE_NAME_SESSION_STATE = "sessionState";
    public static final String MDC_ATTRIBUTE_NAME_VERSION = "serviceVersion";
    public static final String MDC_ATTRIBUTE_CLIENT_IP = "clientIP";
    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";
    private final BuildProperties buildProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if(session != null) {
            MDC.put(MDC_ATTRIBUTE_NAME_SESSION_ID, session.getId());
            TaraSession taraSession = (TaraSession) session.getAttribute(TARA_SESSION);
            if(taraSession != null && taraSession.getState() != null) {
                MDC.put(MDC_ATTRIBUTE_NAME_SESSION_STATE, taraSession.getState().name());
            }
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve
        String requestId = MDC.get("traceId");
        if (isNotEmpty(requestId)) {
            request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestId);
        }

        if (buildProperties != null) {
            MDC.put(MDC_ATTRIBUTE_NAME_VERSION, buildProperties.getVersion());
        }

        String ipAddress = request.getRemoteAddr();
        if (isNotEmpty(ipAddress)) {
            MDC.put(MDC_ATTRIBUTE_CLIENT_IP, ipAddress);
        }

        filterChain.doFilter(request, response);
    }
}