package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.smartid.AuthenticationHash;
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

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class SmartIdController {

    @Autowired
    private AuthSidService authSidService;

    @PostMapping(value = "/auth/sid/init", produces = MediaType.TEXT_HTML_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String authSidInit(@Validated SidCredential sidCredential, Model model, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Initiating Smart-ID authentication session for country: " + sidCredential.getCountryCode());
        validateSession(taraSession);
        AuthenticationHash authenticationHash = authSidService.startSidAuthSession(taraSession, sidCredential.getCountryCode(), sidCredential.getIdCode());
        model.addAttribute("smartIdVerificationCode", authenticationHash.calculateVerificationCode());
        return "sidLoginCode";
    }

    public void validateSession(TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart-ID authentication method is not allowed");
        }
    }

    @Data
    @ValidNationalIdNumber(fieldName = "idCode", dependFieldName = "countryCode")
    public static class SidCredential {
        private String idCode;
        private String countryCode;
    }
}
