package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.smartid.*;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.HttpServerErrorException;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAllowedException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.ProcessingException;
import java.net.SocketTimeoutException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static ee.ria.taraauthserver.error.ErrorCode.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled", matchIfMissing = true)
public class SmartIdController {

    @Autowired
    private SmartIdClient sidClient;

    @Autowired
    private AuthenticationResponseValidator authenticationResponseValidator;

    @Autowired
    private Executor taskExecutor;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private SmartIdConfigurationProperties smartIdConfigurationProperties;

    private static final Map<Class<?>, ErrorCode> errorMap;

    static {
        errorMap = new HashMap<>();
        errorMap.put(InternalServerErrorException.class, SID_INTERNAL_ERROR);
        errorMap.put(ProcessingException.class, SID_REQUEST_TIMEOUT);
        errorMap.put(UserRefusedException.class, SID_USER_REFUSED);
        errorMap.put(SessionTimeoutException.class, SID_SESSION_TIMEOUT);
        errorMap.put(DocumentUnusableException.class, SID_DOCUMENT_UNUSABLE);
        errorMap.put(UserSelectedWrongVerificationCodeException.class, SID_WRONG_VC);
        errorMap.put(RequiredInteractionNotSupportedByAppException.class, SID_INTERACTION_NOT_SUPPORTED);
        errorMap.put(UserRefusedCertChoiceException.class, SID_USER_REFUSED_CERT_CHOICE);
        errorMap.put(UserRefusedDisplayTextAndPinException.class, SID_USER_REFUSED_DISAPLAYTEXTANDPIN);
        errorMap.put(UserRefusedVerificationChoiceException.class, SID_USER_REFUSED_VC_CHOICE);
    }

    @PostMapping(value = "/auth/sid/init", produces = MediaType.TEXT_HTML_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String authSidInit(@Validated @ModelAttribute(value = "credential") SidCredential sidCredential, Model model, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {

        validateSession(taraSession);

        AuthenticationHash authenticationHash = getAuthenticationHash();

        AuthenticationRequestBuilder requestBuilder = sidClient.createAuthentication();
        String sidSessionId = initiateSidAuthenticationSession(sidCredential, taraSession, authenticationHash, requestBuilder);

        CompletableFuture.supplyAsync(() -> pollSidSessionStatus(sidSessionId), taskExecutor)
                .thenAcceptAsync(sessionStatus -> handleSidAuthenticationResult(taraSession, sessionStatus, requestBuilder), taskExecutor)
                .exceptionally(ex -> {
                    handleSidAuthenticationException(taraSession, ex);
                    return null;
                });

        model.addAttribute("smartIdVerificationCode", authenticationHash.calculateVerificationCode());
        return "sidLoginCode";
    }

    AuthenticationHash getAuthenticationHash() {
        return AuthenticationHash.generateRandomHash(HashType.valueOf(smartIdConfigurationProperties.getHashType()));
    }

    private String initiateSidAuthenticationSession(SidCredential sidCredential, TaraSession taraSession, AuthenticationHash authenticationHash, AuthenticationRequestBuilder requestBuilder) {
        try {
            log.info("Initiating smart-id session...");
            taraSession.setState(INIT_SID);
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, sidCredential.getSmartIdCode());
            requestBuilder
                    .withRelyingPartyUUID(getAppropriateRelyingPartyUuid(taraSession))
                    .withRelyingPartyName(getAppropriateRelyingPartyName(taraSession))
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withCertificateLevel("QUALIFIED")
                    .withAuthenticationHash(authenticationHash)
                    .withAllowedInteractionsOrder(getAppropriateAllowedInteractions(taraSession));
            String sidSessionId = requestBuilder.initiateAuthentication();

            log.info("Initiated smart-id session with id: " + sidSessionId);

            taraSession.setState(POLL_SID_STATUS);
            TaraSession.SidAuthenticationResult sidAuthenticationResult = new TaraSession.SidAuthenticationResult(sidSessionId);
            taraSession.setAuthenticationResult(sidAuthenticationResult);

            return sidSessionId;
        } catch (NotAllowedException | SmartIdClientException | NotAuthorizedException e) {
            log.error("Failed to initiate SID authentication session: " + e.getMessage());
            throw new IllegalStateException(ERROR_GENERAL.getMessage(), e);
        } catch (Exception e) {
            log.error("Failed to initiate SID authentication session: " + e.getMessage());
            throw new HttpServerErrorException(HttpStatus.BAD_GATEWAY, SID_INTERNAL_ERROR.getMessage());
        }
    }

    private List<Interaction> getAppropriateAllowedInteractions(TaraSession taraSession) {
        List<Interaction> allowedInteractions = new ArrayList<>();
        allowedInteractions.add(Interaction.displayTextAndPIN(taraSession.getOidcClientTranslatedShortName()));
        if (shouldUseVerificationCodeCheck(taraSession))
            allowedInteractions.add(Interaction.verificationCodeChoice(taraSession.getOidcClientTranslatedShortName()));
        return allowedInteractions;
    }

    private Boolean shouldUseVerificationCodeCheck(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getShouldUseAdditionalVerificationCodeCheck)
                .orElse(false);
    }

    private String getAppropriateRelyingPartyName(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getRelyingPartyUuid)
                .orElse(smartIdConfigurationProperties.getRelyingPartyName());
    }

    private String getAppropriateRelyingPartyUuid(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getOidcClient)
                .map(TaraSession.OidcClient::getSmartIdSettings)
                .map(TaraSession.SmartIdSettings::getRelyingPartyUuid)
                .orElse(smartIdConfigurationProperties.getRelyingPartyUuid());
    }

    public void validateSession(TaraSession taraSession) {
        log.info("AuthSession: {}", taraSession);
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart ID authentication method is not allowed");
        }
    }

    private SessionStatus pollSidSessionStatus(String sidSessionId) {
        SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(sidClient.getSmartIdConnector());
        log.info("starting session status polling with id: " + sidSessionId);
        return sessionStatusPoller.fetchFinalSessionStatus(sidSessionId);
    }

    private void handleSidAuthenticationResult(TaraSession taraSession, SessionStatus sessionStatus, AuthenticationRequestBuilder requestBuilder) {
        log.info("handling sid authentication result");

        SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus);
        AuthenticationIdentity authIdentity = authenticationResponseValidator.validate(response);
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        TaraSession.SidAuthenticationResult taraAuthResult = (TaraSession.SidAuthenticationResult) taraSession.getAuthenticationResult();
        if (authIdentity != null) {
            taraAuthResult.setIdCode(authIdentity.getIdentityNumber());
            taraAuthResult.setCountry(authIdentity.getCountry());
            taraAuthResult.setFirstName(authIdentity.getGivenName());
            taraAuthResult.setLastName(authIdentity.getSurname());
            taraAuthResult.setSubject(authIdentity.getCountry() + authIdentity.getIdentityNumber());
            taraAuthResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(authIdentity.getIdentityNumber()));
        }
        taraAuthResult.setAmr(AuthenticationType.SMART_ID);
        taraAuthResult.setAcr(smartIdConfigurationProperties.getLevelOfAssurance());

        Session session = sessionRepository.findById(taraSession.getSessionId());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);

        log.info("sid authentication result handled");
    }

    private void handleSidAuthenticationException(TaraSession taraSession, Throwable ex) {
        Throwable cause = ex.getCause();
        log.error("received sid poll exception: " + cause.getMessage());
        taraSession.setState(AUTHENTICATION_FAILED);
        taraSession.getAuthenticationResult().setErrorCode(translateExceptionToErrorCode(cause));

        Session session = sessionRepository.findById(taraSession.getSessionId());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private ErrorCode translateExceptionToErrorCode(Throwable ex) {
        return errorMap.getOrDefault(ex.getClass(), ERROR_GENERAL);
    }

    @Data
    public static class SidCredential {
        @ValidNationalIdNumber(message = "{message.mid-rest.error.invalid-identity-code}")
        private String smartIdCode;
    }

}
