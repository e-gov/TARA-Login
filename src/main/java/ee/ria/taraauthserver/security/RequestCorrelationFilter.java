package ee.ria.taraauthserver.security;

import lombok.NonNull;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RequestCorrelationFilter extends OncePerRequestFilter {

    private static final String MDC_ATTRIBUTE_KEY_VERSION = "service.version";
    private static final String MDC_ATTRIBUTE_KEY_CLIENT_IP = "client.ip";
    public static final String MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID = "trace.id";
    private static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";

    private final String version;

    public RequestCorrelationFilter(@NonNull BuildProperties buildProperties, @NonNull GitProperties gitProperties) {
        version = getVersion(buildProperties, gitProperties);
        logger.info("Application version: " + version);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestTraceId = MDC.get(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID);
        if (StringUtils.isEmpty(requestTraceId)) {
            requestTraceId = RandomStringUtils.random(32, "0123456789abcdef");
            MDC.put(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID, requestTraceId);
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve
        request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestTraceId);

        if (version != null) {
            MDC.put(MDC_ATTRIBUTE_KEY_VERSION, version);
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_VERSION);
        }

        String ipAddress = request.getRemoteAddr();
        if (StringUtils.isNotEmpty(ipAddress)) {
            MDC.put(MDC_ATTRIBUTE_KEY_CLIENT_IP, ipAddress);
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_CLIENT_IP);
        }

        filterChain.doFilter(request, response);

        // TODO Ideally all MDC values that are set here should be cleared after request completes - investigate where
        //  is the correct place to do that. Doing it here clears trace.id too early so that error page can not access
        //  it.
        //  As the second-best solution, we are (re)setting _all_ values above at the start of request. Usually request
        //  threads and background threads are not cross-used.
    }

    private String getVersion(BuildProperties buildProperties, GitProperties gitProperties) {
        if (buildProperties != null) {
            String versionWithoutBuildNumber = buildProperties.getVersion();

            if (gitProperties != null) {
                String buildNumber = gitProperties.get("build.number");
                if (StringUtils.isNotEmpty(buildNumber)) {
                    return versionWithoutBuildNumber + "-" + buildNumber;
                }
            }
            return versionWithoutBuildNumber;
        }
        return null;
    }

}
