package ee.ria.taraauthserver.security;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
@RequiredArgsConstructor
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_NAME_VERSION = "service.version";
    public static final String MDC_ATTRIBUTE_CLIENT_IP = "client.ip";
    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";
    private final BuildProperties buildProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestId = MDC.get("trace.id");
        if (isEmpty(requestId)) {
            MDC.put("trace.id", RandomStringUtils.randomAlphanumeric(16).toLowerCase());
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve
        request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestId);

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