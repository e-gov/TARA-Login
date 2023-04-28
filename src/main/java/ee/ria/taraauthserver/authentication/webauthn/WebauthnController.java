package ee.ria.taraauthserver.authentication.webauthn;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.OidcClient;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.servlet.view.RedirectView;

import javax.cache.Cache;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.ArrayList;
import java.util.EnumSet;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_GIVEN;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.CONSENT_NOT_REQUIRED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_WEBAUTHN_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.webauthn.enabled")
public class WebauthnController {
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties taraProperties;

    @Autowired
    private Cache<String, String> webauthnRelayStateCache;

    @PostMapping(value = "/auth/webauthn/login", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView webauthnLogin(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        String relayState = UUID.randomUUID().toString();
        log.info("Initiating Webauthn authentication session with relay state: {}", value("tara.session.eidas.relay_state", relayState));
        validateSession(taraSession, EnumSet.of(INIT_AUTH_PROCESS));
        webauthnRelayStateCache.put(relayState, taraSession.getSessionId());

        updateSession(taraSession, relayState);
        return new RedirectView(taraProperties.getEeidService().getWebauthnLoginUrl() + "?relay_state=" + relayState);
    }

    @PostMapping(value = "/auth/webauthn/register", produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView webauthnRegister(@RequestParam(name = "WebauthnUserId") String webauthnUserId,
                                         @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        String relayState = UUID.randomUUID().toString();
        log.info("Initiating Webauthn registration session with relay state: {}", value("tara.session.eidas.relay_state", relayState));
        validateSession(taraSession, EnumSet.of(CONSENT_GIVEN, CONSENT_NOT_REQUIRED));
        webauthnRelayStateCache.put(relayState, taraSession.getSessionId());

        taraSession.setState(WAITING_WEBAUTHN_RESPONSE);
        return new RedirectView(taraProperties.getEeidService().getWebauthnRegisterUrl() + "?webauthn_user_id=" + webauthnUserId + "&relay_state=" + relayState);
    }

    private void updateSession(TaraSession taraSession, String relayState) {
        TaraSession.WebauthnAuthenticationResult authenticationResult = new TaraSession.WebauthnAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.WEBAUTHN);
        authenticationResult.setRelayState(relayState);
        taraSession.setState(WAITING_WEBAUTHN_RESPONSE);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    public void validateSession(TaraSession taraSession, EnumSet<TaraAuthenticationState> validSessionStates) {
        SessionUtils.assertSessionInState(taraSession, validSessionStates);
        List<String> allowedScopes = getAllowedRequestedScopes(taraSession.getLoginRequestInfo());
        if (!(allowedScopes.contains("webauthn"))) {
            throw new BadRequestException(INVALID_REQUEST, "Webauthn scope is not allowed.");
        }
    }

    @NotNull
    private List<String> getAllowedRequestedScopes(TaraSession.LoginRequestInfo loginRequestInfo) {
        return Arrays.asList(loginRequestInfo.getClient().getScope().split(" "));
    }

}
