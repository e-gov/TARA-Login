package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.smartid.*;
import ee.sk.smartid.rest.SmartIdRestConnector;
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

import java.util.Collections;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled", matchIfMissing = true)
public class SmartIdController {

    @Autowired
    private SmartIdClient sidClient;

    @PostMapping(value = "/auth/sid/init", produces = MediaType.TEXT_HTML_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String authMidInit(@Validated @ModelAttribute(value = "credential") SidRequest sidRequest, Model model, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash(HashType.SHA512);
        String verificationCode = authenticationHash.calculateVerificationCode();
        AuthenticationSessionRequest authenticationSessionRequest = new AuthenticationSessionRequest();
        authenticationSessionRequest.setHash(authenticationHash.getHashInBase64());
        authenticationSessionRequest.setHashType(HashType.SHA512.getHashTypeName());
        authenticationSessionRequest.setCertificateLevel("QUALIFIED");
        authenticationSessionRequest.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")));

        log.info("id code: " + sidRequest.getSmartIdCode());
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, sidRequest.getSmartIdCode());
        AuthenticationSessionResponse response = sidClient.getSmartIdConnector().authenticate(semanticsIdentifier, authenticationSessionRequest);


        log.info("session id and verification code: ");
        log.info(response.getSessionID());
        log.info(verificationCode);

        return "sidLoginCode";
    }

    @Data
    public static class SidRequest {
        @ValidNationalIdNumber(message = "{message.mid-rest.error.invalid-identity-code}")
        private String smartIdCode;
    }

}
