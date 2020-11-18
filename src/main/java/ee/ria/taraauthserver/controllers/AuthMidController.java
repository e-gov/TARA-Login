package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.error.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.utils.SessionUtils;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.mid.*;
import ee.sk.mid.exception.*;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAllowedException;
import javax.ws.rs.ProcessingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;

import static ee.ria.taraauthserver.session.AuthState.*;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(value = "tara.mid-authentication.enabled", matchIfMissing = true)
public class AuthMidController {

    @Autowired
    private MidClient midClient;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties;

    private Map<String, MidLanguage> midLanguages = Map.of(
            "et", MidLanguage.EST,
            "en", MidLanguage.ENG,
            "ru", MidLanguage.RUS);

    @PostMapping(value = "/auth/mid/init", produces = MediaType.TEXT_HTML_VALUE)
    public String authMidInit(@Validated @ModelAttribute(value = "credential") MidRequestBody requestParameters, Model model, HttpSession httpSession) {

        requestParameters.telephoneNumber = "+372" + requestParameters.telephoneNumber;

        Session session = sessionRepository.findById(httpSession.getId());
        if (session == null)
            throw new BadRequestException(ErrorMessages.SESSION_NOT_FOUND, "Invalid session");
        AuthSession authSession = session.getAttribute("session");
        validateAuthSession(authSession);
        log.info("AuthSession: " + authSession);

        MidAuthenticationHashToSign authenticationHash = MidAuthenticationHashToSign.generateRandomHashOfType(MidHashType.valueOf(midAuthConfigurationProperties.getHashType()));

        MidAuthenticationResponse response = createMidAuthSession(requestParameters, authenticationHash, authSession);

        CompletableFuture.supplyAsync(
            () -> midClient.getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionID(), "/authentication/session/" + response.getSessionID())
        ).thenApply(
            midSessionStatus -> handleMidPollResult(requestParameters, session, authSession, authenticationHash, midSessionStatus)
        ).exceptionally(
            exception -> handlePossibleExceptions(session, authSession, exception)
        );

        session.setAttribute("session", authSession);
        sessionRepository.save(session);

        model.addAttribute("mobileIdVerificationCode", authenticationHash.calculateVerificationCode());
        return "midLoginCode";
    }

    private AuthSession handleMidPollResult(MidRequestBody requestParameters, Session session, AuthSession authSession, MidAuthenticationHashToSign authenticationHash, MidSessionStatus midSessionStatus) {
        if (StringUtils.equalsIgnoreCase("COMPLETE", midSessionStatus.getState())) {
            if (StringUtils.equalsIgnoreCase("OK", midSessionStatus.getResult())) {
                try {
                    MidAuthenticationResult midAuthenticationResult = validateAndReturnMidAuthenticationResult(authenticationHash, midSessionStatus);
                    updateAuthSessionWithResult(requestParameters, session, authSession, midAuthenticationResult);
                } catch (Exception e) {
                    log.info("EXCEPTION: " + e.getMessage(), e);
                }
            }
        }
        return authSession;
    }

    private void updateAuthSessionWithResult(MidRequestBody requestParameters, Session session, AuthSession authSession, MidAuthenticationResult midAuthenticationResult) {
        String idCode = midAuthenticationResult.getAuthenticationIdentity().getIdentityCode();
        authSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        AuthSession.MidAuthenticationResult authenticationResult = new AuthSession.MidAuthenticationResult();

        authenticationResult.setIdCode(midAuthenticationResult.getAuthenticationIdentity().getIdentityCode());
        authenticationResult.setCountry(midAuthenticationResult.getAuthenticationIdentity().getCountry());
        authenticationResult.setFirstName(midAuthenticationResult.getAuthenticationIdentity().getGivenName());
        authenticationResult.setLastName(midAuthenticationResult.getAuthenticationIdentity().getSurName());
        authenticationResult.setPhoneNumber(requestParameters.getTelephoneNumber());
        authenticationResult.setSubject(midAuthenticationResult.getAuthenticationIdentity().getCountry() + midAuthenticationResult.getAuthenticationIdentity().getIdentityCode());
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAmr(AuthenticationType.MobileID);
        authenticationResult.setAcr(midAuthConfigurationProperties.getLevelOfAssurance());

        authSession.setAuthenticationResult(authenticationResult);
        session.setAttribute("session", authSession);
        sessionRepository.save(session);
    }

    private AuthSession handlePossibleExceptions(Session session, AuthSession authSession, Throwable e) {
        if (e.getCause() instanceof javax.ws.rs.BadRequestException) {
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof javax.ws.rs.NotAuthorizedException) {
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidSessionNotFoundException) {
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof NotAllowedException) {
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof InternalServerErrorException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_INTERNAL_ERROR);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidNotMidClientException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.NOT_MID_CLIENT);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidSessionTimeoutException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_TRANSACTION_EXPIRED);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(500);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidUserCancellationException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_USER_CANCEL);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidInvalidUserConfigurationException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_HASH_MISMATCH);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(500);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidPhoneNotAvailableException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_PHONE_ABSENT);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidDeliveryException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_DELIVERY_ERROR);
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        if (e.getCause() instanceof MidInternalErrorException) {
            ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_INTERNAL_ERROR);
            setSessionStateFailed(session, authSession, e.getMessage());
        }
        return null;
    }

    private void setSessionStateFailed(Session session, AuthSession authSession, String message) {
        log.info("Mid polling failed: " + message);
        authSession.setState(AUTHENTICATION_FAILED);
        session.setAttribute("session", authSession);
        sessionRepository.save(session);
    }

    private void validateAuthSession(AuthSession authSession) {

        if (authSession == null) {
            throw new BadRequestException(ErrorMessages.SESSION_NOT_FOUND, "authSession is null");
        }
        if (authSession.getState() != INIT_AUTH_PROCESS) {
            throw new BadRequestException(ErrorMessages.SESSION_STATE_INVALID, "authSession state should be " + INIT_AUTH_PROCESS + " but was " + authSession.getState());
        }
        if (!authSession.getAllowedAuthMethods().contains(AuthenticationType.MobileID)) {
            throw new BadRequestException(ErrorMessages.INVALID_REQUEST, "Mobile ID authentication method is not allowed");
        }
        authSession.setState(INIT_MID);
    }

    private MidAuthenticationResponse createMidAuthSession(MidRequestBody requestParameters, MidAuthenticationHashToSign authenticationHash, AuthSession authSession) {

        MidAuthenticationRequest midRequest = createMidAuthenticationRequest(requestParameters, authenticationHash);

        try {
            log.info("Mid request: " + midRequest.toString());
            MidAuthenticationResponse response = midClient.getMobileIdConnector().authenticate(midRequest);
            log.info("Mid response: " + response.toString());
            updateAuthSessionWithInitResponse(authSession, response);
            return response;
        } catch (MidInternalErrorException | ProcessingException e) {
            throw new ServiceNotAvailableException(ErrorMessages.MID_INTERNAL_ERROR, String.format("MID service is currently unavailable: %s", e.getMessage()), e);
        } catch (Exception e) {
            throw new IllegalStateException("Internal error during MID authentication init: " + e.getMessage(), e);
        }
    }

    private void updateAuthSessionWithInitResponse(AuthSession authSession, MidAuthenticationResponse response) {
        authSession.setState(POLL_MID_STATUS);
        AuthSession.MidAuthenticationResult midAuthenticationResult = new AuthSession.MidAuthenticationResult();
        authSession.setAuthenticationResult(midAuthenticationResult);
        midAuthenticationResult.setMidSessionId(response.getSessionID());
    }

    private MidAuthenticationRequest createMidAuthenticationRequest(MidRequestBody requestParameters, MidAuthenticationHashToSign authenticationHash) {
        String translatedShortName = getTranslatedShortName(SessionUtils.getAuthSession());
        MidAuthenticationRequest midRequest = MidAuthenticationRequest.newBuilder()
                .withPhoneNumber(requestParameters.getTelephoneNumber())
                .withNationalIdentityNumber(requestParameters.getIdCode())
                .withHashToSign(authenticationHash)
                .withLanguage(getMidLanguage())
                .withDisplayText(translatedShortName)
                .withDisplayTextFormat(isServiceNameUsingSpecialCharacters(translatedShortName) ? MidDisplayTextFormat.UCS2 : MidDisplayTextFormat.GSM7)
                .build();
        return midRequest;
    }

    private String getTranslatedShortName(AuthSession authSession) {
        String translatedShortName = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getShortName();

        if (authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations() != null) {
            Map<String, String> serviceNameTranslations = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
            Locale locale = LocaleContextHolder.getLocale();
            if (serviceNameTranslations.containsKey(locale.getLanguage()))
                translatedShortName = serviceNameTranslations.get(locale.getLanguage());
        }
        return translatedShortName;
    }

    private static boolean isServiceNameUsingSpecialCharacters(String serviceName) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("[а-яА-ЯЁё]", java.util.regex.Pattern.CASE_INSENSITIVE);
        String[] specialCharacters = {"Õ", "Š", "Ž", "š", "ž", "õ", "Ą", "Č", "Ę", "Ė", "Į", "Š", "Ų", "Ū", "Ž", "ą", "č", "ę", "ė", "į", "š", "ų", "ū", "ž"};
        Matcher m = p.matcher(serviceName);
        boolean isSpecialCharacterIncluded = m.find();
        return Arrays.stream(specialCharacters).anyMatch(serviceName::contains) || isSpecialCharacterIncluded;
    }

    private MidAuthenticationResult validateAndReturnMidAuthenticationResult(MidAuthenticationHashToSign authenticationHash, MidSessionStatus midSessionStatus) {
        try {
            MidAuthentication authentication = midClient.createMobileIdAuthentication(midSessionStatus, authenticationHash);
            MidAuthenticationResponseValidator validator = new MidAuthenticationResponseValidator(getMidTrustStore());
            return validator.validate(authentication);
        } catch (Exception e) {
            log.error("Error when validating mid authentication result - " + e.getCause().getMessage());
            throw new IllegalStateException("Internal server error when validating mid authentication result.");
        }
    }

    public KeyStore getMidTrustStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        log.info("getting mid truststore");
        InputStream is = getClass().getClassLoader().getResourceAsStream(midAuthConfigurationProperties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(midAuthConfigurationProperties.getTruststoreType());
        trustStore.load(is, midAuthConfigurationProperties.getTruststorePassword().toCharArray());
        return trustStore;
    }

    private MidLanguage getMidLanguage() {
        Locale locale = LocaleContextHolder.getLocale();
        return midLanguages.get(locale.getLanguage());
    }

    @Data
    @ToString
    public static class MidRequestBody {
        @ValidNationalIdNumber(message = "{message.mid-rest.error.invalid-identity-code}")
        private String idCode;
        @NotNull(message = "{message.mid-rest.error.invalid-phone-number}")
        @Pattern(regexp = "\\d{8,15}", message = "{message.mid-rest.error.invalid-phone-number}")
        private String telephoneNumber;
    }
}
