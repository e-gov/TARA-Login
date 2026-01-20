package ee.ria.taraauthserver.authentication.smartid.qrcode;


import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Locale;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_STATE_INVALID;
import static ee.ria.taraauthserver.session.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;
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
    private final MessageSource messageSource;

    @PostMapping(value = "/auth/sid/qr-code/init", produces = MediaType.TEXT_HTML_VALUE)
    public String initAuthentication(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Initiating Smart-ID QR code authentication session");
        assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        validateSmartIdAuthenticationAllowed(taraSession);

        authSidQrCodeService.startAuthentication(taraSession);
        return QR_CODE_VIEW;
    }

    @ResponseBody
    @GetMapping(value = "/auth/sid/qr-code/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    public PollResponse pollStatus(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Polling Smart-ID QR code authentication status");
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }
        TaraAuthenticationState state = taraSession.getState();
        switch (state) {
            case NATURAL_PERSON_AUTHENTICATION_COMPLETED:
                return PollResponse.completed();
            case INIT_SID_QR_CODE:
            case POLL_SID_QR_CODE:
                Locale locale = RequestUtils.getLocale();
                String deviceLink = authSidQrCodeService.getDeviceLink(taraSession, locale);
                return PollResponse.pending(deviceLink);
            case AUTHENTICATION_FAILED:
                ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
                return PollResponse.failed(errorCode, messageSource);
            default:
                return PollResponse.failed(SESSION_STATE_INVALID, messageSource);
        }
    }

    @PostMapping(value = "/auth/sid/qr-code/cancel", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView cancelAuthentication(
            @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Canceling Smart-ID QR code authentication");
        assertSessionInState(taraSession, Set.of(INIT_SID_QR_CODE, POLL_SID_QR_CODE));

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

    public record PollResponse(
            @NonNull Status status,
            String deviceLink,
            ErrorCode error,
            String message
    ) {

        public static PollResponse pending(String deviceLink) {
            return new PollResponse(
                    Status.PENDING,
                    deviceLink,
                    null,
                    null
            );
        }

        public static PollResponse completed() {
            return new PollResponse(
                    Status.COMPLETED,
                    null,
                    null,
                    null
            );
        }

        public static PollResponse failed(ErrorCode errorCode, MessageSource messageSource) {
            return new PollResponse(
                    Status.FAILED,
                    null,
                    errorCode,
                    messageSource.getMessage(errorCode.getMessage(), null, RequestUtils.getLocale())
            );
        }

        public enum Status {
            PENDING,
            COMPLETED,
            FAILED
        }

    }

}
