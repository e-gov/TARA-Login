package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.OidcClient;
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

import javax.cache.Cache;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EIDAS_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
public class EidasController {
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.EIDAS, this.getClass());

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private RestTemplate eidasRestTemplate;

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    @PostMapping(value = "/auth/eidas/init", produces = MediaType.TEXT_HTML_VALUE)
    public String EidasInit(@RequestParam("country") String country, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession, HttpServletResponse servletResponse) {
        String relayState = UUID.randomUUID().toString();
        log.info("Initiating EIDAS authentication session with relay state: {}", value("tara.session.eidas.relay_state", relayState));
        validateSession(taraSession);
        eidasRelayStateCache.put(relayState, taraSession.getSessionId()); // TODO AUT-854

        if (!eidasConfigurationProperties.getAvailableCountries().contains(country)) {
            throw new BadRequestException(getAppropriateErrorCode(), "Requested country not supported.");
        }

        String requestUrl = createRequestUrl(country, taraSession, relayState);

        requestLogger.logRequest(requestUrl, HttpMethod.GET);
        var response = eidasRestTemplate.exchange(
                requestUrl,
                HttpMethod.GET,
                null,
                String.class);
        requestLogger.logResponse(response);

        updateSession(country, taraSession, relayState);
        return getHtmlRedirectPageFromResponse(servletResponse, response);
    }

    @Nullable
    private String getHtmlRedirectPageFromResponse(HttpServletResponse servletResponse, ResponseEntity<String> response) {
        servletResponse.setHeader("Content-Security-Policy", "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src '" + eidasConfigurationProperties.getScriptHash() + "' 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content");
        return response.getBody();
    }

    private void updateSession(String country, TaraSession taraSession, String relayState) {
        TaraSession.EidasAuthenticationResult authenticationResult = new TaraSession.EidasAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.EIDAS);
        authenticationResult.setRelayState(relayState);
        authenticationResult.setCountry(country);
        taraSession.setState(WAITING_EIDAS_RESPONSE);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    private String createRequestUrl(String country, TaraSession taraSession, String relayState) {
        String url = eidasConfigurationProperties.getClientUrl() + "/login";
        OidcClient oidcClient = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("Country", country)
                .queryParam("RequesterID", oidcClient.getEidasRequesterId())
                .queryParam("SPType", oidcClient.getInstitution().getSector())
                .queryParam("RelayState", relayState);
        List<String> acr = getAcrFromSessionOidcContext(taraSession);
        if (acr != null)
            builder.queryParam("LoA", acr.get(0).toUpperCase());
        return builder.toUriString();
    }

    private ErrorCode getAppropriateErrorCode() {
        List<String> allowedCountries = eidasConfigurationProperties.getAvailableCountries();
        ErrorCode errorCode = ErrorCode.EIDAS_COUNTRY_NOT_SUPPORTED;
        Object[] messageParameters = new Object[1];
        messageParameters[0] = String.join(", ", allowedCountries);
        errorCode.setMessageParameters(messageParameters);
        return errorCode;
    }

    private List<String> getAcrFromSessionOidcContext(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getOidcContext)
                .map(TaraSession.OidcContext::getAcrValues)
                .orElse(null);
    }

    public void validateSession(TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        List<String> allowedScopes = getAllowedRequestedScopes(taraSession.getLoginRequestInfo());
        if (!(allowedScopes.contains("eidas") || allowedScopes.contains("eidasonly"))) {
            throw new BadRequestException(INVALID_REQUEST, "Neither eidas or eidasonly scope is allowed.");
        }
    }

    @NotNull
    private List<String> getAllowedRequestedScopes(TaraSession.LoginRequestInfo loginRequestInfo) {
        return Arrays.asList(loginRequestInfo.getClient().getScope().split(" "));
    }

}
