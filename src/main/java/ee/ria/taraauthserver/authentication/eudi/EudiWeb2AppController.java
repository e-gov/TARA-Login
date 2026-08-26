package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.RequestUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static ee.ria.taraauthserver.error.ErrorCode.EUDI_CALLBACK_SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_NOT_REQUIRED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.GET_LEGAL_PERSON_LIST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_CALLBACK;
import static ee.ria.taraauthserver.utils.RequestUtils.LANG_PARAM_NAME;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.eudi-wallet.enabled")
@RequiredArgsConstructor
public class EudiWeb2AppController {
    public static final String EUDI_VIEW = "eudiView";
    public static final String EUDI_CALLBACK_VIEW = "eudiCallback";
    public static final String WEB2APP_LINK_MODEL_ATTRIBUTE = "eudiWeb2AppLink";

    private final AuthEudiService authEudiService;

    @PostMapping(value = "/auth/eudi/web2app/init", produces = MediaType.TEXT_HTML_VALUE)
    public String initAuthentication(TaraSession taraSession, Model model) {
        log.info("Initiating EUDI wallet Web2App authentication session");
        validateSession(taraSession, INIT_AUTH_PROCESS);

        String web2AppLink = authEudiService.startWeb2AppAuthSession(taraSession);
        model.addAttribute(WEB2APP_LINK_MODEL_ATTRIBUTE, web2AppLink);
        return EUDI_VIEW;
    }

    @GetMapping(value = "/auth/eudi/callback", produces = MediaType.TEXT_HTML_VALUE)
    public String callback(Optional<TaraSession> optionalTaraSession,
                           @RequestParam(name = "response_code", required = false) String responseCode,
                           HttpServletResponse response) {
        log.info("Handling EUDI wallet Web2App callback");
        // The URL carries a one-time response code; keep it out of the Referer of anything this page leads to.
        response.setHeader("Referrer-Policy", "no-referrer");
        TaraSession taraSession = optionalTaraSession.orElseThrow(() ->
            new BadRequestException(EUDI_CALLBACK_SESSION_NOT_FOUND, "Session not found on EUDI wallet callback"));
        validateSession(taraSession, WAITING_EUDI_CALLBACK);

        authEudiService.completeWeb2AppAuthentication(taraSession, responseCode);
        return EUDI_CALLBACK_VIEW;
    }

    @ResponseBody
    @GetMapping(value = "/auth/eudi/web2app/poll", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> pollAuthentication(Optional<TaraSession> optionalTaraSession) {
        log.info("Polling EUDI wallet Web2App authentication status");
        if (optionalTaraSession.isEmpty()) {
            return Map.of("status", "ENDED");
        }
        TaraSession taraSession = optionalTaraSession.get();
        validateSession(taraSession,
            WAITING_EUDI_CALLBACK,
            NATURAL_PERSON_AUTHENTICATION_COMPLETED,
            LEGAL_PERSON_AUTHENTICATION_INIT,
            GET_LEGAL_PERSON_LIST,
            LEGAL_PERSON_AUTHENTICATION_COMPLETED,
            AUTHENTICATION_SUCCESS,
            INIT_CONSENT_PROCESS,
            CONSENT_NOT_REQUIRED);
        if (taraSession.getState() != WAITING_EUDI_CALLBACK) {
            return Map.of("status", "COMPLETED");
        }
        authEudiService.pollWeb2AppAuthentication(taraSession);
        return Map.of("status", "PENDING");
    }

    @PostMapping(value = "/auth/eudi/web2app/cancel", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView cancelAuthentication(TaraSession taraSession) {
        log.info("Canceling EUDI wallet Web2App authentication");
        validateSession(taraSession, WAITING_EUDI_CALLBACK);

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

    private static void validateSession(TaraSession taraSession, TaraAuthenticationState... allowedStates) {
        SessionUtils.assertSessionInState(taraSession, Set.of(allowedStates));
        if (!taraSession.getAllowedAuthMethods().contains(AuthenticationType.EUDI_WALLET)) {
            throw new BadRequestException(INVALID_REQUEST, "EUDI wallet authentication method is not allowed");
        }
    }

}
