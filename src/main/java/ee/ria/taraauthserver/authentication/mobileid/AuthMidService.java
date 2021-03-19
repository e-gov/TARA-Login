package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MidAuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.*;
import ee.sk.mid.exception.*;
import ee.sk.mid.rest.MidLoggingFilter;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ProcessingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static ee.ria.taraauthserver.error.ErrorCode.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Arrays.stream;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static java.util.regex.Pattern.compile;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Slf4j
@Service
@ConditionalOnProperty(value = "tara.auth-methods.mobile-id.enabled")
public class AuthMidService {
    private static final String[] SPECIAL_CHARS = {"Õ", "Š", "Ž", "š", "ž", "õ", "Ą", "Č", "Ę", "Ė", "Į", "Š", "Ų", "Ū", "Ž", "ą", "č", "ę", "ė", "į", "š", "ų", "ū", "ž"};
    private static final java.util.regex.Pattern serviceNameRegex = compile("[а-яА-ЯЁё]", CASE_INSENSITIVE);
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
        errorMap.put(MidMissingOrInvalidParameterException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidUnauthorizedException.class, MID_INTEGRATION_ERROR);
        errorMap.put(MidNotMidClientException.class, NOT_MID_CLIENT);
        errorMap.put(MidSessionTimeoutException.class, MID_TRANSACTION_EXPIRED);
        errorMap.put(MidUserCancellationException.class, MID_USER_CANCEL);
        errorMap.put(MidInvalidUserConfigurationException.class, MID_HASH_MISMATCH);
        errorMap.put(MidPhoneNotAvailableException.class, MID_PHONE_ABSENT);
        errorMap.put(MidDeliveryException.class, MID_DELIVERY_ERROR);
        errorMap.put(ProcessingException.class, MID_INTERNAL_ERROR);
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
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private Executor taskExecutor;

    public MidAuthenticationHashToSign startMidAuthSession(TaraSession taraSession, String idCode, String telephoneNumber) {
        try {
            MidAuthenticationHashToSign authenticationHash = getAuthenticationHash();
            MidAuthenticationResponse midAuthentication = initMidAuthentication(taraSession, idCode, telephoneNumber, authenticationHash);
            CompletableFuture.runAsync(() -> pollAuthenticationResult(taraSession, authenticationHash, midAuthentication, telephoneNumber), taskExecutor);
            return authenticationHash;
        } catch (MidInternalErrorException | ProcessingException e) {
            throw new ServiceNotAvailableException(MID_INTERNAL_ERROR, String.format("MID service is currently unavailable: %s", e.getMessage()), e);
        } catch (Exception e) {
            throw new IllegalStateException("Internal error during MID authentication init: " + e.getMessage(), e);
        }
    }

    MidAuthenticationHashToSign getAuthenticationHash() {
        return MidAuthenticationHashToSign.generateRandomHashOfType(MidHashType.valueOf(midAuthConfigurationProperties.getHashType()));
    }

    private MidAuthenticationResponse initMidAuthentication(TaraSession taraSession, String idCode, String telephoneNumber, MidAuthenticationHashToSign authenticationHash) {
        taraSession.setState(INIT_MID);
        String shortName = defaultIfNull(taraSession.getOidcClientTranslatedShortName(), midAuthConfigurationProperties.getDisplayText());

        MidClient midClient = getAppropriateMidClient(taraSession);
        MidAuthenticationRequest midRequest = createMidAuthenticationRequest(idCode, telephoneNumber, authenticationHash, shortName, midClient);
        MidAuthenticationResponse response = midClient.getMobileIdConnector().authenticate(midRequest);
        updateAuthSessionWithInitResponse(taraSession, response);
        return response;
    }

    private MidAuthenticationRequest createMidAuthenticationRequest(String idCode, String telephoneNumber, MidAuthenticationHashToSign authenticationHash, String translatedShortName, MidClient midClient) {
        MidAuthenticationRequest midRequest = MidAuthenticationRequest.newBuilder()
                .withNationalIdentityNumber(idCode)
                .withPhoneNumber(telephoneNumber)
                .withHashToSign(authenticationHash)
                .withLanguage(getMidLanguage())
                .withDisplayText(translatedShortName)
                .withDisplayTextFormat(isServiceNameUsingSpecialCharacters(translatedShortName) ? MidDisplayTextFormat.UCS2 : MidDisplayTextFormat.GSM7)
                .withRelyingPartyUUID(midClient.getRelyingPartyUUID())
                .withRelyingPartyName(midClient.getRelyingPartyName())
                .build();
        log.info(append("tara.session.mid_authentication_init_request", midRequest), "Mobile ID authentication init request");
        return midRequest;
    }

    private void updateAuthSessionWithInitResponse(TaraSession taraSession, MidAuthenticationResponse response) {
        taraSession.setState(POLL_MID_STATUS);
        TaraSession.MidAuthenticationResult midAuthenticationResult = new TaraSession.MidAuthenticationResult(response.getSessionID());
        taraSession.setAuthenticationResult(midAuthenticationResult);
        log.info(append(TARA_SESSION, taraSession), "Mobile ID authentication process with MID session id {} has been initiated", response.getSessionID());
    }

    private static boolean isServiceNameUsingSpecialCharacters(String serviceName) {
        boolean isSpecialCharacterIncluded = serviceNameRegex.matcher(serviceName).find();
        return stream(SPECIAL_CHARS).anyMatch(serviceName::contains) || isSpecialCharacterIncluded;
    }

    private void pollAuthenticationResult(TaraSession taraSession, MidAuthenticationHashToSign authenticationHash, MidAuthenticationResponse response, String telephoneNumber) {
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        MDC.put("labels.tara_trace_id", taraTraceId);
        log.info("Polling Mobile ID authentication process with MID session id {}",
                value("tara.session.authentication_result.mid_session_id", response.getSessionID()));
        try {
            MidSessionStatus midSessionStatus = midClient.getSessionStatusPoller()
                    .fetchFinalSessionStatus(response.getSessionID(), "/authentication/session/" + response.getSessionID());
            handleAuthenticationResult(taraSession, authenticationHash, midSessionStatus, telephoneNumber);
        } catch (Exception ex) {
            handleAuthenticationException(taraSession, ex);
        }
    }

    private void handleAuthenticationResult(TaraSession taraSession, MidAuthenticationHashToSign authenticationHash, MidSessionStatus midSessionStatus, String telephoneNumber) {
        if (midSessionStatus != null) {
            String midSessionId = ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId();
            log.info("MID session id {} authentication result: {}, status: {}",
                    value("tara.session.authentication_result.mid_session_id", midSessionId),
                    value("tara.session.authentication_result.mid_result", midSessionStatus.getResult()),
                    value("tara.session.authentication_result.mid_state", midSessionStatus.getState()));

            if (equalsIgnoreCase("COMPLETE", midSessionStatus.getState()) && equalsIgnoreCase("OK", midSessionStatus.getResult())) {
                MidAuthentication authentication = midClient.createMobileIdAuthentication(midSessionStatus, authenticationHash);
                MidAuthenticationResult midAuthResult = midAuthenticationResponseValidator.validate(authentication);
                TaraSession.MidAuthenticationResult taraAuthResult = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();

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
                    log.error("Authentication result validation failed: {}",
                            value("tara.session.authentication_result.mid_errors", midAuthResult.getErrors()));
                }
                Session session = sessionRepository.findById(taraSession.getSessionId());
                if (session != null) {
                    session.setAttribute(TARA_SESSION, taraSession);
                    sessionRepository.save(session);
                } else {
                    log.debug("Session not found: {}", taraSession.getSessionId());
                }
            }
        }
    }

    private void handleAuthenticationException(TaraSession taraSession, Exception ex) {
        try {
            taraSession.setState(AUTHENTICATION_FAILED);
            ErrorCode errorCode = translateExceptionToErrorCode(ex);
            taraSession.getAuthenticationResult().setErrorCode(errorCode);
            log.warn(append(TARA_SESSION, taraSession)
                            .and(append("error.code", errorCode.name())),
                    "Mobile ID polling failed: {}", value("error.message", ex.getMessage()));
            Session session = sessionRepository.findById(taraSession.getSessionId());
            if (session != null) {
                session.setAttribute(TARA_SESSION, taraSession);
                sessionRepository.save(session);
            } else {
                log.debug("Session not found: {}", taraSession.getSessionId());
            }
        } catch (Exception e) {
            log.error("Failed to write session: " + ex.getMessage(), e);
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
        clientConfig.register(new MidLoggingFilter());
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
                .map(TaraSession.MidSettings::getRelyingPartyUuid)
                .orElse(null);
    }
}
