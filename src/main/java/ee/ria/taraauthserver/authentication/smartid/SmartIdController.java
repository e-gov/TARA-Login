package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.rest.MidSessionStatusPoller;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import ee.sk.smartid.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

import javax.ws.rs.ProcessingException;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.MID_INTERNAL_ERROR;
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

    @PostMapping(value = "/auth/sid/init", produces = MediaType.TEXT_HTML_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String authSidInit(@Validated @ModelAttribute(value = "credential") SidRequest sidRequest, Model model, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {

        validateSession(taraSession);
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash(HashType.SHA512);
        String verificationCode = authenticationHash.calculateVerificationCode();

        log.info("id code: " + sidRequest.getSmartIdCode());

        try {
            AuthenticationRequestBuilder requestBuilder = sidClient.createAuthentication();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, sidRequest.getSmartIdCode());
            requestBuilder
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withCertificateLevel("QUALIFIED")
                    .withAuthenticationHash(authenticationHash)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?"))).authenticate();
            String sidSessionId = requestBuilder.initiateAuthentication();

            CompletableFuture.supplyAsync(() -> pollSidSessionStatus(sidSessionId), taskExecutor)
                    .thenAcceptAsync(sessionStatus -> handleSidAuthenticationResult(taraSession, sessionStatus, requestBuilder), taskExecutor)
                    .exceptionally(ex -> {
                        handleSidAuthenticationException(taraSession, ex);
                        return null;
                    });
        } catch (Exception e) {
            throw new IllegalStateException("Internal error during MID authentication init: " + e.getMessage(), e);
        }

        taraSession.setState(POLL_SID_STATUS);
        model.addAttribute("smartIdVerificationCode", verificationCode);
        return "sidLoginCode";
    }

    public void validateSession(TaraSession taraSession) {
        log.info("AuthSession: {}", taraSession);
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        /*if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart ID authentication method is not allowed");
        }*/
    }

    private SessionStatus pollSidSessionStatus(String sidSessionId) {
        SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(sidClient.getSmartIdConnector());
        log.info("starting session status polling with id: " + sidSessionId);
        return sessionStatusPoller.fetchFinalSessionStatus(sidSessionId);
    }

    private void handleSidAuthenticationResult(TaraSession taraSession, SessionStatus sessionStatus, AuthenticationRequestBuilder requestBuilder) {
        log.info("handling sid authentication result");
        log.info(taraSession.toString());
        SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus);
        AuthenticationIdentity authIdentity = authenticationResponseValidator.validate(response);
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        TaraSession.AuthenticationResult taraAuthResult = taraSession.getAuthenticationResult();
        if (authIdentity != null) {
            taraAuthResult.setIdCode(authIdentity.getIdentityNumber());
            taraAuthResult.setCountry(authIdentity.getCountry());
            taraAuthResult.setFirstName(authIdentity.getGivenName());
            taraAuthResult.setLastName(authIdentity.getSurname());
            taraAuthResult.setSubject(authIdentity.getCountry() + authIdentity.getIdentityNumber());
            taraAuthResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(authIdentity.getIdentityNumber()));
        }
        log.info("identity from response is:");
        log.info(taraSession.toString());
    }

    private void handleSidAuthenticationException(TaraSession taraSession, Throwable ex) {
        taraSession.setState(AUTHENTICATION_FAILED);
        log.info("received sid authentication exception: " + ex.getMessage());
    }

    @Data
    public static class SidRequest {
        @ValidNationalIdNumber(message = "{message.mid-rest.error.invalid-identity-code}")
        private String smartIdCode;
    }

}
