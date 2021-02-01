package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MidAuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.*;
import ee.sk.mid.exception.*;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ProcessingException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static ee.ria.taraauthserver.error.ErrorCode.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Arrays.stream;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static java.util.regex.Pattern.compile;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Slf4j
@Service
@ConditionalOnProperty(value = "tara.auth-methods.mobile-id.enabled", matchIfMissing = true)
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
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private MidAuthenticationResponseValidator midAuthenticationResponseValidator;

    @Autowired
    private MidAuthConfigurationProperties midAuthConfigurationProperties;

    @Autowired
    private Executor taskExecutor;

    public MidAuthenticationHashToSign startMidAuthSession(TaraSession taraSession, String idCode, String telephoneNumber) {
        try {
            MidAuthenticationHashToSign authenticationHash = getAuthenticationHash();
            MidAuthenticationResponse midAuthentication = initMidAuthentication(taraSession, idCode, telephoneNumber, authenticationHash);
            CompletableFuture.supplyAsync(() -> pollAuthenticationResult(midAuthentication), taskExecutor)
                    .thenAcceptAsync(midSessionStatus -> handleAuthenticationResult(taraSession, authenticationHash, midSessionStatus, telephoneNumber), taskExecutor)
                    .exceptionally(ex -> {
                        handleAuthenticationException(taraSession, ex);
                        return null;
                    });
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
        String translatedShortName = taraSession.getOidcClientTranslatedShortName();

        MidAuthenticationRequest midRequest = createMidAuthenticationRequest(idCode, telephoneNumber, authenticationHash, translatedShortName);
        MidAuthenticationResponse response = midClient.getMobileIdConnector().authenticate(midRequest);
        log.info("Mid init response: {}", response);

        updateAuthSessionWithInitResponse(taraSession, response);
        return response;
    }

    private MidAuthenticationRequest createMidAuthenticationRequest(String idCode, String telephoneNumber, MidAuthenticationHashToSign authenticationHash, String translatedShortName) {
        MidAuthenticationRequest midRequest = MidAuthenticationRequest.newBuilder()
                .withNationalIdentityNumber(idCode)
                .withPhoneNumber(telephoneNumber)
                .withHashToSign(authenticationHash)
                .withLanguage(getMidLanguage())
                .withDisplayText(translatedShortName)
                .withDisplayTextFormat(isServiceNameUsingSpecialCharacters(translatedShortName) ? MidDisplayTextFormat.UCS2 : MidDisplayTextFormat.GSM7)
                .build();
        log.info("Mid init request: {}", midRequest);
        return midRequest;
    }

    private void updateAuthSessionWithInitResponse(TaraSession taraSession, MidAuthenticationResponse response) {
        log.info("Mobile ID authentication process with MID session id {} has been initiated", response.getSessionID());
        taraSession.setState(POLL_MID_STATUS);
        TaraSession.MidAuthenticationResult midAuthenticationResult = new TaraSession.MidAuthenticationResult(response.getSessionID());
        taraSession.setAuthenticationResult(midAuthenticationResult);
    }

    private static boolean isServiceNameUsingSpecialCharacters(String serviceName) {
        boolean isSpecialCharacterIncluded = serviceNameRegex.matcher(serviceName).find();
        return stream(SPECIAL_CHARS).anyMatch(serviceName::contains) || isSpecialCharacterIncluded;
    }

    private MidSessionStatus pollAuthenticationResult(MidAuthenticationResponse response) {
        log.info("Polling Mobile ID authentication process with MID session id {}", response.getSessionID());
        return midClient.getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionID(), "/authentication/session/" + response.getSessionID());
    }

    private void handleAuthenticationResult(TaraSession taraSession, MidAuthenticationHashToSign authenticationHash, MidSessionStatus midSessionStatus, String telephoneNumber) {
        if (midSessionStatus != null) {
            log.info("MID session id {} authentication result: {}", ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getMidSessionId(), midSessionStatus.getState());
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
                    log.error("Authentication result validation failed: {}", midAuthResult.getErrors());
                }
                Session session = sessionRepository.findById(taraSession.getSessionId());
                session.setAttribute(TARA_SESSION, taraSession);
                sessionRepository.save(session);
            }
        }
    }

    private void handleAuthenticationException(TaraSession taraSession, Throwable ex) {
        Throwable cause = ex.getCause();
        log.warn("Mid polling failed: {}", cause.getMessage());
        taraSession.setState(AUTHENTICATION_FAILED);
        taraSession.getAuthenticationResult().setErrorCode(translateExceptionToErrorCode(cause));

        Session session = sessionRepository.findById(taraSession.getSessionId());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private MidLanguage getMidLanguage() {
        return midLanguages.get(LocaleContextHolder.getLocale().getLanguage());
    }

    private ErrorCode translateExceptionToErrorCode(Throwable ex) {
        return errorMap.getOrDefault(ex.getClass(), ERROR_GENERAL);
    }
}
