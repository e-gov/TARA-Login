package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Set;

import static ee.ria.taraauthserver.authentication.eudi.EudiWeb2AppController.EUDI_VIEW;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_DC_API_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;
import static ee.ria.taraauthserver.utils.RequestUtils.LANG_PARAM_NAME;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.eudi-wallet.enabled")
@RequiredArgsConstructor
public class EudiDigitalCredentialsController {
    public static final String DC_API_REQUEST_MODEL_ATTRIBUTE = "eudiDcApiRequest";
    private static final int DC_API_ERROR_NAME_MAX_LENGTH = 64;
    private static final int DC_API_ERROR_MESSAGE_MAX_LENGTH = 512;

    private final AuthEudiService authEudiService;

    @PostMapping(value = "/auth/eudi/dc-api/init", produces = MediaType.TEXT_HTML_VALUE)
    public String initAuthentication(TaraSession taraSession, Model model) {
        log.info("Initiating EUDI wallet Digital Credentials API authentication session");
        validateSession(taraSession, INIT_AUTH_PROCESS);

        String requestObject = authEudiService.startDcApiAuthSession(taraSession);
        model.addAttribute(DC_API_REQUEST_MODEL_ATTRIBUTE, requestObject);
        return EUDI_VIEW;
    }

    @PostMapping(value = "/auth/eudi/dc-api/response", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> response(TaraSession taraSession,
                                         @RequestBody(required = false) WalletResponse walletResponse) {
        log.info("Handling EUDI wallet Digital Credentials API response");
        validateSession(taraSession, WAITING_EUDI_DC_API_RESPONSE);

        authEudiService.completeDcApiAuthentication(taraSession, walletResponse);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(value = "/auth/eudi/dc-api/error", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void error(TaraSession taraSession, @RequestBody DcApiError dcApiError) {
        validateSession(taraSession, WAITING_EUDI_DC_API_RESPONSE);

        String errorName = StringUtils.abbreviate(dcApiError.name(), DC_API_ERROR_NAME_MAX_LENGTH);
        String errorMessage = StringUtils.abbreviate(dcApiError.message(), DC_API_ERROR_MESSAGE_MAX_LENGTH);
        log.error(append("tara.session.eudi.dc_api_error_message", errorMessage),
            "Client-side Digital Credentials API error: {}",
            value("tara.session.eudi.dc_api_error_name", errorName));
        throw new BadRequestException(EUDI_DC_API_ERROR, "Client-side Digital Credentials API error: " + errorName);
    }

    @PostMapping(value = "/auth/eudi/dc-api/cancel", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView cancelAuthentication(TaraSession taraSession) {
        log.info("Canceling EUDI wallet Digital Credentials API authentication");
        validateSession(taraSession, WAITING_EUDI_DC_API_RESPONSE);

        authEudiService.cancelAuthentication(taraSession);

        URIBuilder authInitUriBuilder = new URIBuilder()
            .appendPath("/auth/init")
            .addParameter("login_challenge", taraSession.getLoginRequestInfo().getChallenge());
        String chosenLanguage = RequestUtils.getLangParamValue(taraSession);
        if (chosenLanguage != null) {
            authInitUriBuilder.addParameter(LANG_PARAM_NAME, chosenLanguage);
        }
        return new RedirectView(authInitUriBuilder.toString());
    }

    /**
     * The {@code name} and {@code message} of the DOMException that {@code navigator.credentials.get} rejected with.
     */
    record DcApiError(String name, String message) {
    }

    private static void validateSession(TaraSession taraSession, TaraAuthenticationState... allowedStates) {
        SessionUtils.assertSessionInState(taraSession, Set.of(allowedStates));
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.EUDI_WALLET)) {
            throw new BadRequestException(INVALID_REQUEST, "EUDI wallet authentication method is not allowed");
        }
    }

}
