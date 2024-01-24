package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.AuthFlowTimeoutException;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.error.exceptions.TaraException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.UnknownContentTypeException;
import org.springframework.web.client.UnknownHttpStatusCodeException;

import java.io.IOException;

import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.error.ErrorAttributes.ERROR_ATTR_REDIRECT_TO_SERVICE_PROVIDER;
import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {
    private final StatisticsLogger statisticsLogger;

    private void invalidateSessionAndSendError(HttpServletRequest request, HttpServletResponse response, int status, Exception ex) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            TaraSession taraSession = (TaraSession) requireNonNull(session.getAttribute(TARA_SESSION));
            setErrorCode(taraSession, ex);
            if (!AUTHENTICATION_FAILED.equals(taraSession.getState())) {
                taraSession.setState(AUTHENTICATION_FAILED);
                statisticsLogger.log(taraSession, ex);
            }
            if (taraSession.getLoginRequestInfo() != null) {
                request.setAttribute(ERROR_ATTR_LOGIN_CHALLENGE, taraSession.getLoginRequestInfo().getChallenge());
            }
            session.invalidate();
            log.warn(append(TARA_SESSION, taraSession), "Session has been invalidated: {}", session.getId());
        }

        response.sendError(status);
    }

    private void setErrorCode(TaraSession taraSession, Exception ex) {
        if (ex instanceof TaraException &&
                taraSession.getAuthenticationResult() != null &&
                taraSession.getAuthenticationResult().getErrorCode() == null) {
            taraSession.getAuthenticationResult().setErrorCode(defaultIfNull(((TaraException) ex).getErrorCode(), INTERNAL_ERROR));
        } else if (taraSession.getAuthenticationResult() != null &&
                taraSession.getAuthenticationResult().getErrorCode() == null) {
            taraSession.getAuthenticationResult().setErrorCode(INTERNAL_ERROR);
        }
    }

    @ExceptionHandler({BadRequestException.class})
    public void handleBadRequestException(BadRequestException ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (ex.getCause() != null)
            log.error(append("error.code", ex.getErrorCode().name()), "User exception: {}", ex.getMessage(), ex);
        else {
            log.error(append("error.code", ex.getErrorCode().name()), "User exception: {}", ex.getMessage());
        }
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_BAD_REQUEST, ex);
    }

    @ExceptionHandler({BindException.class, ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public void handleBindException(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled())
            log.error("User input exception: {}", ex.getMessage(), ex);
        else
            log.error("User input exception: {}", ex.getMessage());
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_BAD_REQUEST, ex);
    }

    @ExceptionHandler({HttpClientErrorException.class})
    public void handleRestClientResponseException(HttpClientErrorException ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ex);
    }

    @ExceptionHandler({ServiceNotAvailableException.class, HttpServerErrorException.class, UnknownHttpStatusCodeException.class, UnknownContentTypeException.class, ResourceAccessException.class})
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

    @ExceptionHandler({AuthFlowTimeoutException.class})
    public void handleAuthFlowTimeoutException(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            TaraSession taraSession = (TaraSession) requireNonNull(session.getAttribute(TARA_SESSION));
            if (!AUTHENTICATION_FAILED.equals(taraSession.getState())) {
                taraSession.setState(AUTHENTICATION_FAILED);
                statisticsLogger.log(taraSession, ex);
            }
        }
        request.setAttribute(ERROR_ATTR_REDIRECT_TO_SERVICE_PROVIDER, true);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.error("Server encountered an unexpected error: {}", ex.getMessage(), ex);
        invalidateSessionAndSendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ex);
    }
}
