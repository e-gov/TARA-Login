package ee.ria.taraauthserver.authentication.mobileid;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MidAuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.MidValidationException;
import ee.ria.taraauthserver.logging.JaxRsClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidAuthenticationIdentity;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidAuthenticationResult;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidDisplayTextFormat;
import ee.sk.mid.MidHashType;
import ee.sk.mid.MidLanguage;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.mid.exception.MidDeliveryException;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.exception.MidInvalidUserConfigurationException;
import ee.sk.mid.exception.MidMissingOrInvalidParameterException;
import ee.sk.mid.exception.MidNotMidClientException;
import ee.sk.mid.exception.MidPhoneNotAvailableException;
import ee.sk.mid.exception.MidSessionNotFoundException;
import ee.sk.mid.exception.MidSessionTimeoutException;
import ee.sk.mid.exception.MidUnauthorizedException;
import ee.sk.mid.exception.MidUserCancellationException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAllowedException;
import javax.ws.rs.ProcessingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static co.elastic.apm.api.Outcome.FAILURE;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.MID_DELIVERY_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.MID_HASH_MISMATCH;
import static ee.ria.taraauthserver.error.ErrorCode.MID_INTEGRATION_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.MID_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.MID_PHONE_ABSENT;
import static ee.ria.taraauthserver.error.ErrorCode.MID_TRANSACTION_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.MID_USER_CANCEL;
import static ee.ria.taraauthserver.error.ErrorCode.MID_VALIDATION_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.NOT_MID_CLIENT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_MID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdc;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdcAndLocale;
import static java.lang.String.format;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.CompletableFuture.delayedExecutor;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@Service
@ConditionalOnProperty(value = "tara.auth-methods.mobile-id.enabled")
public class AuthMidService {
    private static final String GSM_7_CHARACTERS = "@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞ^{}[~]|€ÆæßÉ!\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà \r\n\\";
    private static final Map<String, MidLanguage> midLanguages = Map.of(
            "et", MidLanguage.EST,
            "en", MidLanguage.ENG,
            "ru", MidLanguage.RUS);

    private static final Map<Class<?>, ErrorCode> errorMap;

    static {
        errorMap = new HashMap<>();
        errorMap.put(InternalServerErrorException.class, MID_INTERNAL_ERROR);
        errorMap.put(MidInternalErrorException.class, MID_INTERNAL_ERROR);
        errorMap.put(MidSessionNotFoundException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidMissingOrInvalidParameterException.class, ERROR_GENERAL);
        errorMap.put(MidUnauthorizedException.class, ERROR_GENERAL);
        errorMap.put(MidNotMidClientException.class, NOT_MID_CLIENT);
        errorMap.put(MidSessionTimeoutException.class, MID_TRANSACTION_EXPIRED);
        errorMap.put(MidUserCancellationException.class, MID_USER_CANCEL);
        errorMap.put(MidInvalidUserConfigurationException.class, MID_HASH_MISMATCH);
        errorMap.put(MidPhoneNotAvailableException.class, MID_PHONE_ABSENT);
        errorMap.put(MidDeliveryException.class, MID_DELIVERY_ERROR);
        errorMap.put(ProcessingException.class, MID_INTERNAL_ERROR);
        errorMap.put(NotAllowedException.class, ERROR_GENERAL);
        errorMap.put(MidValidationException.class, MID_VALIDATION_ERROR);
    }

    @Autowired
    private MidClient midClient;

    @Autowired
    private SSLContext sslContext;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private MidAuthenticationResponseValidator midAuthenticationResponseValidator;

    @Autowired
    private MidAuthConfigurationProperties midAuthConfigurationProperties;

    @Autowired
    private Executor taskExecutor;

    @Autowired
    private StatisticsLogger statisticsLogger;

    public MidAuthenticationHashToSign startMidAuthSession(TaraSession taraSession, String idCode, String telephoneNumber) {
        taraSession.setState(INIT_MID);
        MidAuthenticationHashToSign authenticationHash = getAuthenticationHash();
        MidLanguage midLanguage = getMidLanguage();

        CompletableFuture
                .supplyAsync(withMdcAndLocale(() -> initAuthentication(taraSession, idCode, telephoneNumber, authenticationHash, midLanguage)),
                        delayedExecutor(midAuthConfigurationProperties.getDelayInitiateMidSessionInMilliseconds(), MILLISECONDS, taskExecutor))
                .thenAcceptAsync(withMdc((midAuthentication) -> pollAuthenticationResult(taraSession, authenticationHash, midAuthentication, telephoneNumber)),
                        delayedExecutor(midAuthConfigurationProperties.getDelayStatusPollingStartInMilliseconds(), MILLISECONDS, taskExecutor));

        return authenticationHash;
    }

    MidAuthenticationHashToSign getAuthenticationHash() {
        return MidAuthenticationHashToSign.generateRandomHashOfType(MidHashType.valueOf(midAuthConfigurationProperties.getHashType()));
    }

    private MidAuthenticationResponse initAuthentication(TaraSession taraSession, String idCode, String telephoneNumber, MidAuthenticationHashToSign authenticationHash, MidLanguage midLanguage) {
        Span span = ElasticApm.currentTransaction().startSpan("app", "MID", "poll");
        span.setName("AuthMidService#initAuthentication");
        span.setStartTimestamp(now().plus(200, MILLIS).minus(midAuthConfigurationProperties.getDelayInitiateMidSessionInMilliseconds(), MILLIS).toEpochMilli() * 1_000);

        try (final Scope scope = span.activate()) {
            String shortName = defaultIfNull(taraSession.getOidcClientTranslatedShortName(), midAuthConfigurationProperties.getDisplayText());
            MidClient midClient = getAppropriateMidClient(taraSession);
            MidAuthenticationRequest midRequest = createMidAuthenticationRequest(idCode, telephoneNumber, authenticationHash, shortName, midClient, midLanguage);
            MidAuthenticationResponse response = midClient.getMobileIdConnector().authenticate(midRequest);
            taraSession.setState(POLL_MID_STATUS);
            String midSessionId = response.getSessionID();
            createMidAuthenticationResult(taraSession, midSessionId);
            log.info("Initiated Mobile-ID session with id: {}", value("tara.session.authentication_result.mid_session_id", midSessionId));
            return response;
        } catch (Exception e) {
            createMidAuthenticationResult(taraSession, null);
            handleAuthenticationException(taraSession, e);
            handleStatisticsLogging(taraSession, e);
        } finally {
            updateSession(taraSession);
            span.end();
        }
        return null;
    }

    private MidAuthenticationRequest createMidAuthenticationRequest(String idCode, String telephoneNumber, MidAuthenticationHashToSign authenticationHash, String translatedShortName, MidClient midClient, MidLanguage midLanguage) {
        return MidAuthenticationRequest.newBuilder()
                .withNationalIdentityNumber(idCode)
                .withPhoneNumber(telephoneNumber)
                .withHashToSign(authenticationHash)
                .withLanguage(midLanguage)
                .withDisplayText(translatedShortName)
                .withDisplayTextFormat(containsNonGsm7Characters(translatedShortName) ? MidDisplayTextFormat.UCS2 : MidDisplayTextFormat.GSM7)
                .withRelyingPartyUUID(midClient.getRelyingPartyUUID())
                .withRelyingPartyName(midClient.getRelyingPartyName())
                .build();
    }

    private void createMidAuthenticationResult(TaraSession taraSession, String sessionId) {
        TaraSession.MidAuthenticationResult midAuthenticationResult = new TaraSession.MidAuthenticationResult(sessionId);
        midAuthenticationResult.setAmr(AuthenticationType.MOBILE_ID);
        taraSession.setAuthenticationResult(midAuthenticationResult);
    }

    private void updateSession(TaraSession taraSession) {
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session != null) {
            session.setAttribute(TARA_SESSION, taraSession);
            sessionRepository.save(session);
        } else {
            log.error("Session correlated with this Mobile-ID polling process was not found: {}", taraSession.getSessionId());
        }
    }

    private static boolean containsNonGsm7Characters(String serviceName) {
        for (int i = 0; i < serviceName.length(); i++) {
            if (GSM_7_CHARACTERS.indexOf(serviceName.charAt(i)) == -1) {
                return true;
            }
        }
        return false;
    }

    private void pollAuthenticationResult(TaraSession taraSession, MidAuthenticationHashToSign authenticationHash, MidAuthenticationResponse response, String telephoneNumber) {
        if (response != null) {
            Span span = ElasticApm.currentTransaction().startSpan("app", "MID", "poll");
            span.setName("AuthMidService#pollAuthenticationResult");
            span.setStartTimestamp(now().plus(200, MILLIS).minus(midAuthConfigurationProperties.getDelayStatusPollingStartInMilliseconds(), MILLIS).toEpochMilli() * 1_000);
            try (final Scope scope = span.activate()) {
                String midSessionId = response.getSessionID();
                log.info("Starting Mobile-ID session status polling with id: {}", value("tara.session.sid_authentication_result.mid_session_id", midSessionId));
                MidSessionStatus midSessionStatus = midClient.getSessionStatusPoller()
                        .fetchFinalSessionStatus(midSessionId, "/authentication/session/" + midSessionId);
                handleAuthenticationResult(taraSession, authenticationHash, midSessionStatus, telephoneNumber);
                statisticsLogger.logExternalTransaction(taraSession);
            } catch (Exception ex) {
                handleAuthenticationException(taraSession, ex);
                handleStatisticsLogging(taraSession, ex);
            } finally {
                updateSession(taraSession);
                span.end();
            }
        }
    }

    private void handleAuthenticationResult(TaraSession taraSession, MidAuthenticationHashToSign authenticationHash, MidSessionStatus midSessionStatus, String telephoneNumber) {
        TaraSession.MidAuthenticationResult taraAuthResult = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        String midSessionId = taraAuthResult.getMidSessionId();
        log.info("MID session id {} authentication result: {}, status: {}",
                value("tara.session.authentication_result.mid_session_id", midSessionId),
                value("tara.session.authentication_result.mid_result", midSessionStatus.getResult()),
                value("tara.session.authentication_result.mid_state", midSessionStatus.getState()));

        MidAuthentication authentication = midClient.createMobileIdAuthentication(midSessionStatus, authenticationHash);
        MidAuthenticationResult midAuthResult = midAuthenticationResponseValidator.validate(authentication);

        MidAuthenticationIdentity authIdentity = midAuthResult.getAuthenticationIdentity();
        if (authIdentity != null) {
            taraAuthResult.setIdCode(authIdentity.getIdentityCode());
            taraAuthResult.setCountry(authIdentity.getCountry());
            taraAuthResult.setFirstName(authIdentity.getGivenName());
            taraAuthResult.setLastName(authIdentity.getSurName());
            taraAuthResult.setSubject(authIdentity.getCountry() + authIdentity.getIdentityCode());
            taraAuthResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(authIdentity.getIdentityCode()));
        }
        taraAuthResult.setPhoneNumber(telephoneNumber);
        taraAuthResult.setAmr(AuthenticationType.MOBILE_ID);
        taraAuthResult.setAcr(midAuthConfigurationProperties.getLevelOfAssurance());

        if (midAuthResult.isValid() && midAuthResult.getErrors().isEmpty()) {
            taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        } else {
            taraSession.setState(AUTHENTICATION_FAILED);
            taraAuthResult.setErrorCode(MID_VALIDATION_ERROR);
            throw new MidValidationException(format("Authentication result validation failed: %s", midAuthResult.getErrors()));
        }
    }

    private void handleAuthenticationException(TaraSession taraSession, Exception ex) {
        taraSession.setState(AUTHENTICATION_FAILED);
        ErrorCode errorCode = translateExceptionToErrorCode(ex);
        taraSession.getAuthenticationResult().setErrorCode(errorCode);

        if (ERROR_GENERAL == errorCode || MID_INTERNAL_ERROR == errorCode) {
            log.error(append("error.code", errorCode.name()), "Mobile-ID authentication exception: {}", ex.getMessage(), ex);
        } else if (MID_VALIDATION_ERROR == errorCode) {
            log.error(append("error.code", errorCode.name()), ex.getMessage(), ex);
        } else {
            log.warn("Mobile-ID authentication failed: {}, Error code: {}", value("error.message", ex.getMessage()), value("error.code", errorCode.name()));
        }

        Span span = ElasticApm.currentSpan();
        span.setOutcome(FAILURE);
        span.captureException(ex);
    }

    private void handleStatisticsLogging(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
        if (ERROR_GENERAL == errorCode || MID_INTERNAL_ERROR == errorCode || MID_VALIDATION_ERROR == errorCode) {
            statisticsLogger.logExternalTransaction(taraSession, ex);
        } else {
            statisticsLogger.logExternalTransaction(taraSession);
        }
    }

    private MidLanguage getMidLanguage() {
        return midLanguages.get(LocaleContextHolder.getLocale().getLanguage());
    }

    private ErrorCode translateExceptionToErrorCode(Throwable ex) {
        return errorMap.getOrDefault(ex.getClass(), ERROR_GENERAL);
    }

    private MidClient getAppropriateMidClient(TaraSession taraSession) {
        String relyingPartyUuid = getRelyingPartyUuidFromClientRequest(taraSession);
        String relyingPartyName = getRelyingPartyNameFromClientRequest(taraSession);
        if (relyingPartyUuid == null || relyingPartyName == null)
            return midClient;
        else
            return createNewMidClient(relyingPartyUuid, relyingPartyName);
    }

    private MidClient createNewMidClient(String relyingPartyUuid, String relyingPartyName) {
        return MidClient.newBuilder()
                .withHostUrl(midAuthConfigurationProperties.getHostUrl())
                .withRelyingPartyUUID(relyingPartyUuid)
                .withRelyingPartyName(relyingPartyName)
                .withTrustSslContext(sslContext)
                .withNetworkConnectionConfig(createMidClientConfig())
                .withLongPollingTimeoutSeconds(midAuthConfigurationProperties.getLongPollingTimeoutSeconds())
                .build();
    }

    private ClientConfig createMidClientConfig() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, midAuthConfigurationProperties.getConnectionTimeoutMilliseconds());
        clientConfig.property(ClientProperties.READ_TIMEOUT, midAuthConfigurationProperties.getReadTimeoutMilliseconds());
        clientConfig.register(new JaxRsClientRequestLogger("Mobile-ID"));
        return clientConfig;
    }

    private String getRelyingPartyUuidFromClientRequest(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getMidSettings)
                .map(TaraSession.MidSettings::getRelyingPartyUuid)
                .orElse(null);
    }

    private String getRelyingPartyNameFromClientRequest(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getMidSettings)
                .map(TaraSession.MidSettings::getRelyingPartyName)
                .orElse(null);
    }
}
