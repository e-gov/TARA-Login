package ee.ria.taraauthserver.authentication.smartid.qrcode;


import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.LANG_PARAM_NAME;

@Slf4j
@Validated
@Controller
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.qr-code.enabled"
        },
        havingValue = "true"
)
@RequiredArgsConstructor
public class SmartIdQrCodeController {

    public static final String QR_CODE_VIEW = "sidQrCode";
    private final AuthSidQrCodeService authSidQrCodeService;

    @PostMapping(value = "/auth/sid/qr-code/init", produces = MediaType.TEXT_HTML_VALUE)
    public String initAuthentication(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Initiating Smart-ID QR code authentication session");
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        validateSmartIdAuthenticationAllowed(taraSession);

        authSidQrCodeService.startAuthentication(taraSession);
        return QR_CODE_VIEW;
    }

    @PostMapping(value = "/auth/sid/qr-code/cancel", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView cancelAuthentication(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Canceling Smart-ID QR code authentication");
        SessionUtils.assertSessionInState(taraSession, INIT_SID_QR_CODE);

        authSidQrCodeService.cancelAuthentication(taraSession);

        URIBuilder authInitUriBuilder = new URIBuilder()
                .appendPath("/auth/init")
                .addParameter("login_challenge", taraSession.getLoginRequestInfo().getChallenge());
        String chosenLanguage = RequestUtils.getLangParamValue(taraSession);
        if (chosenLanguage != null) {
            authInitUriBuilder.addParameter(LANG_PARAM_NAME, chosenLanguage);
        }
        return new RedirectView(authInitUriBuilder.toString());
    }

    private void validateSmartIdAuthenticationAllowed(TaraSession taraSession) {
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.SMART_ID)) {
            throw new BadRequestException(INVALID_REQUEST, "Smart-ID authentication method is not allowed");
        }
    }

}
