package ee.ria.taraauthserver.authentication.veriff;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.VeriffConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.VeriffAuthenticationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.HttpClientErrorException;
import ee.ria.taraauthserver.error.exceptions.VerificationException;
import org.springframework.web.client.RestClientException;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ProcessingException;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import static co.elastic.apm.api.Outcome.FAILURE;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_THREAD_INTERRUPTED_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_MAX_ATTEMPTS_REACHED_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_ABANDONED;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_DECLINED;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_REVIEW_REQUESTED;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_RESUBMISSION_REQUESTED;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_NOT_STARTED_ERROR;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_VERIFF;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.VERIFICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_VERIFF_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdcAndLocale;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.CompletableFuture.delayedExecutor;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@Service
@ConditionalOnProperty(value = "tara.auth-methods.veriff.enabled")
public class VeriffService {
    private static final EnumSet<TaraAuthenticationState> ALLOWED_STATES = EnumSet.of(INIT_VERIFF, POLL_VERIFF_STATUS);
    public static final String APPROVED_STATUS = "approved";
    public static final String NOT_STARTED_STATUS = "not_started";
    public static final String RESUBMISSION_STATUS = "resubmission_requested";
    public static final String REVIEW_STATUS = "review";
    public static final String DECLINED_STATUS = "declined";
    public static final String EXPIRED_STATUS = "expired";
    public static final String ABANDONED_STATUS = "abandoned";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private VeriffConfigurationProperties veriffConfigurationProperties;

    @Autowired
    private Executor taskExecutor;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @Autowired
    private RestTemplate eeidRestTemplate;

    public void startVeriffSession(TaraSession taraSession, String sessionId, String sessionUrl) {
        taraSession.setState(INIT_VERIFF);

        CompletableFuture
                .supplyAsync(withMdcAndLocale(() -> pollVerificationResult(sessionId, sessionUrl, taraSession)),
                        delayedExecutor(veriffConfigurationProperties.getDelayStatusPollingStartInMilliseconds(), MILLISECONDS, taskExecutor));
    }

    private void updateSession(TaraSession taraSession) {
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session != null) {
            session.setAttribute(TARA_SESSION, taraSession);
            sessionRepository.save(session);
        } else {
            log.error("Session correlated with this Veriff polling process was not found: {}", taraSession.getSessionId());
        }
    }

    private String pollVerificationResult(String sessionId, String sessionUrl, TaraSession taraSession) {
        if (sessionId != null) {
            taraSession.setState(POLL_VERIFF_STATUS);

            try {
                log.info("Starting Veriff session status polling with id: {}", sessionId);
                VeriffStatusResponse statusResponse = pollForStatus(sessionId, taraSession);
                handleVerificationResult(taraSession, sessionId, statusResponse);
                statisticsLogger.logExternalTransaction(taraSession);
            } catch (Exception ex) {
                handleVerificationException(taraSession, ex);
                handleStatisticsLogging(taraSession, ex);
            }
        }

        return null;
    }

    private boolean validateSession(TaraSession taraSession) {
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session != null) {
            TaraAuthenticationState state = ((TaraSession) session.getAttribute(TARA_SESSION)).getState();
            if (!ALLOWED_STATES.contains(state))
                return false;
        } else {
            return false;
        } 

        return true;
    }

    private VeriffStatusResponse pollForStatus(String sessionId, TaraSession taraSession) {
        int currentAttempt = 0;
        String[] errorCodeMessageParams = null;

        while (currentAttempt < veriffConfigurationProperties.getMaxSessionStatusQueries()) {
            // Make sure polling stops when state changes or verification cancelled
            if (!validateSession(taraSession))
                return null;

            String requestUrl = veriffConfigurationProperties.getClientUrl() + "/api/v1/veriff/sessions/" + sessionId;
            
            try {
                var response = eeidRestTemplate.exchange(
                    requestUrl,
                    HttpMethod.GET,
                    null,
                    VeriffStatusResponse.class);
                VeriffStatusResponse statusResponse = response.getBody();
                String status = statusResponse.getStatus();
                String reason = statusResponse.getReason();
                if (reason != null) {
                    errorCodeMessageParams = new String[1];
                    errorCodeMessageParams[0] = reason;
                } 

                // Handle various statuses
                switch (status) {
                  case APPROVED_STATUS:
                      return statusResponse;
                  case NOT_STARTED_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_NOT_STARTED_ERROR, "The verification session was not started.");
                  case RESUBMISSION_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_RESUBMISSION_REQUESTED, "Resubmission has been requested.", errorCodeMessageParams);
                  case REVIEW_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_REVIEW_REQUESTED, "The verification session needs to be reviewed.");
                  case DECLINED_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_DECLINED, "The end-user has not been verified.", errorCodeMessageParams);
                  case EXPIRED_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_EXPIRED, "The verification session has been expired.");
                  case ABANDONED_STATUS:
                      throw new VerificationException(ErrorCode.VERIFF_ABANDONED, "The verification session has been abandoned.");
                  default:
                      break; // continue polling
              }
            } catch (RestClientException e) {
                throw new VerificationException(ErrorCode.VERIFF_INTERNAL_ERROR, e.getMessage());
            }

            currentAttempt++;
            try {
                TimeUnit.SECONDS.sleep(veriffConfigurationProperties.getIntervalBetweenSessionStatusQueriesInSeconds());  // Wait before next poll
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VerificationException(ErrorCode.VERIFF_THREAD_INTERRUPTED_ERROR, "Polling thread was interrupted.");
            }
        }

        // If polling reached max attempts without an "approved" status
        throw new VerificationException(ErrorCode.VERIFF_MAX_ATTEMPTS_REACHED_ERROR, "Maximum polling attempts reached without a conclusive status.");
    }

    private void handleVerificationResult(TaraSession taraSession, String sessionId, VeriffStatusResponse statusResponse) {
        if (statusResponse != null) {
            VeriffAuthenticationResult authResult = (VeriffAuthenticationResult) taraSession.getAuthenticationResult();
            
            log.info("Veriff session id {} verification status: {}", sessionId, statusResponse.getStatus());
            IdentityAttributes identity = statusResponse.getIdentityAttributes();

            if (identity != null) {
                authResult.setIdCode(identity.getIdNumber());
                authResult.setCountry(identity.getCountry());
                authResult.setFirstName(identity.getFirstName());
                authResult.setLastName(identity.getLastName());
                authResult.setSubject(identity.getCountry() + identity.getIdNumber());
                if (identity.getDateOfBirth() != null) 
                    authResult.setDateOfBirth(LocalDate.parse(identity.getDateOfBirth()));
            }
            
            authResult.setAmr(AuthenticationType.VERIFF);
            authResult.setAcr(veriffConfigurationProperties.getLevelOfAssurance());

            taraSession.setState(VERIFICATION_COMPLETED);
            updateSession(taraSession);
        }
    }

    private void handleVerificationException(TaraSession taraSession, Exception ex) {
        taraSession.setState(VERIFICATION_FAILED);

        ErrorCode errorCode = translateExceptionToErrorCode(ex);
        String[] reason = translateExceptionToErrorCodeMessageParams(ex);

        taraSession.getAuthenticationResult().setErrorCode(errorCode);
        taraSession.getAuthenticationResult().setReason(reason);

        if (ERROR_GENERAL == errorCode || VERIFF_INTERNAL_ERROR == errorCode) {
            log.error(append("error.code", errorCode.name()), "Veriff ID verification exception: {}", ex.getMessage(), ex);
        } else {
            log.warn("Veriff ID verification failed: {}, Error code: {}", value("error.message", ex.getMessage()), value("error.code", errorCode.name()));
        }

        updateSession(taraSession);
    }

    private void handleStatisticsLogging(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
        if (ERROR_GENERAL == errorCode || VERIFF_INTERNAL_ERROR == errorCode) {
            statisticsLogger.logExternalTransaction(taraSession, ex);
        } else {
            statisticsLogger.logExternalTransaction(taraSession);
        }
    }

    private ErrorCode translateExceptionToErrorCode(Throwable ex) {
        try {
            // Attempt to get the method from the exception
            Method method = ex.getClass().getMethod("getErrorCode");

            // If the method exists, invoke it and return its value
            if (method != null) {
                Object result = method.invoke(ex);
                if (result instanceof ErrorCode) {
                    return (ErrorCode) result;
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            // These exceptions indicate the method doesn't exist or there was an issue invoking it
            // Do nothing here and proceed to return ERROR_GENERAL below
        }

        return ERROR_GENERAL;
    }

    private String[] translateExceptionToErrorCodeMessageParams(Throwable ex) {
        try {
            // Attempt to get the method from the exception
            Method method = ex.getClass().getMethod("getErrorCodeMessageParameters");

            // If the method exists, invoke it and return its value
            if (method != null) {
                Object result = method.invoke(ex);
                if (result instanceof String[]) {
                    return (String[]) result;
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            // These exceptions indicate the method doesn't exist or there was an issue invoking it
            // Do nothing here and proceed to return empty String[] below
        }

        return null;
    }

    @Data
    private static class VeriffStatusResponse implements Serializable {
        @NotBlank
        @JsonProperty("status")
        private String status;
        @JsonProperty("reason_code")
        private String reasonCode;
        @JsonProperty("reason")
        private String reason;
        @JsonProperty("identity_attributes")
        private IdentityAttributes identityAttributes;
    }

    @Data
    private static class IdentityAttributes implements Serializable {
        @NotBlank
        @JsonProperty("first_name")
        private String firstName;
        @NotBlank
        @JsonProperty("last_name")
        private String lastName;
        @NotNull
        @JsonProperty("country")
        private String country;
        @NotNull
        @JsonProperty("id_number")
        private String idNumber;
        @JsonProperty("date_of_birth")
        private String DateOfBirth;
    }
}