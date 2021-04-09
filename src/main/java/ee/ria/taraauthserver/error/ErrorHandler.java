package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.slf4j.Logger;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.ConstraintViolationException;
import java.io.IOException;
import java.util.Locale;

import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_LOCALE;
import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.marker.Markers.append;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {
    private static final Logger statisticsLog = getLogger("statistics");

    private void invalidateSessionAndSendError(HttpServletRequest request, HttpServletResponse response, int status, Exception ex) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Locale locale = (Locale) session.getAttribute(LOCALE_SESSION_ATTRIBUTE_NAME);
            request.setAttribute(ERROR_ATTR_LOCALE, locale);
            TaraSession taraSession = (TaraSession) session.getAttribute(TARA_SESSION);
            LogstashMarker marker = append(TARA_SESSION, taraSession);
            if (taraSession != null) {
                taraSession.setState(AUTHENTICATION_FAILED);
                statisticsLog.error(marker, "Authentication failed with exception", ex);
                if (taraSession.getLoginRequestInfo() != null) {
                    request.setAttribute(ERROR_ATTR_LOGIN_CHALLENGE, taraSession.getLoginRequestInfo().getChallenge());
                }
            }
            session.invalidate();
            log.warn(marker, "Session has been invalidated: {}", session.getId());
        }
        response.sendError(status);
    }

    @ExceptionHandler({BadRequestException.class, BindException.class, ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public void handleBindException(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled())
            log.error("User exception: {}", ex.getMessage(), ex);
        else
            log.error("User exception: {}", ex.getMessage());
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_BAD_REQUEST, ex);
    }

    @ExceptionHandler({HttpClientErrorException.class})
    public void handleHttpClientErrorException(HttpClientErrorException ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.error("HTTP client exception: {}", ex.getMessage(), ex);
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ex);
    }

    @ExceptionHandler({ServiceNotAvailableException.class})
    public void handleDownstreamServiceErrors(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.error("Service not available: {}", ex.getMessage(), ex);
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_BAD_GATEWAY, ex);
    }

    @ExceptionHandler({NotFoundException.class})
    public void handleNotFound(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled())
            log.error("Results not found: {}", ex.getMessage(), ex);
        else
            log.error("Results not found: {}", ex.getMessage());
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_NOT_FOUND, ex);
    }

    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.error("Server encountered an unexpected error: {}", ex.getMessage(), ex);
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ex);
    }
}
