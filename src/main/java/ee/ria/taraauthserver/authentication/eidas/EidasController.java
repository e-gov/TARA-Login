package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.EidasInternalException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled", matchIfMissing = true)
public class EidasController {

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    RestTemplate restTemplate;

    @PostMapping(value = "/auth/eidas/init", produces = MediaType.TEXT_HTML_VALUE)
    public String EidasInit(@Validated @ModelAttribute(value = "credential") Credential credential, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession, HttpServletResponse servletResponse) {

        validateSession(taraSession);

        String relayState = UUID.randomUUID().toString();

        if (!eidasConfigurationProperties.getCountries().contains(credential.getCountry()))
            throw new BadRequestException(getAppropriateErrorCode(), "Requested country not supported.");

        String url = createRequestUrl(credential, taraSession, relayState);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, null, String.class);
            updateSession(credential, taraSession, relayState);
            return getHtmlRedirectPageFromResponse(servletResponse, response);
        } catch (Exception e) {
            log.error("Initializing the eidas authentication process failed - " + e.getMessage());
            throw new EidasInternalException(ErrorCode.ERROR_GENERAL, e.getMessage());
        }
    }

    @Nullable
    private String getHtmlRedirectPageFromResponse(HttpServletResponse servletResponse, ResponseEntity<String> response) {
        servletResponse.setHeader("Content-Security-Policy", "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content");
        return response.getBody();
    }

    private void updateSession(Credential credential, TaraSession taraSession, String relayState) {
        TaraSession.EidasAuthenticationResult authenticationResult = new TaraSession.EidasAuthenticationResult();
        authenticationResult.setRelayState(relayState);
        authenticationResult.setCountry(credential.getCountry());
        taraSession.setState(WAITING_EIDAS_RESPONSE);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    private String createRequestUrl(Credential credential, TaraSession taraSession, String relayState) {
        String url = eidasConfigurationProperties.getClientUrl() + "/login";
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("Country", credential.getCountry())
                .queryParam("RelayState", relayState);
        List<String> acr = getAcrFromSessionOidcContext(taraSession);
        if (acr != null)
            builder.queryParam("LoA", acr.get(0));
        return builder.toUriString();
    }

    private ErrorCode getAppropriateErrorCode() {
        Object[] allowedCountries = eidasConfigurationProperties.getCountries().toArray(new Object[eidasConfigurationProperties.getCountries().size()]);
        ErrorCode test = ErrorCode.EIDAS_COUNTRY_NOT_SUPPORTED;
        test.setContent(allowedCountries);
        return test;
    }

    private List<String> getAcrFromSessionOidcContext(TaraSession taraSession) {
        return Optional.of(taraSession)
                .map(TaraSession::getLoginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getOidcContext)
                .map(TaraSession.OidcContext::getAcrValues)
                .orElse(null);
    }

    public void validateSession(TaraSession taraSession) {
        log.info("AuthSession: {}", taraSession);
        SessionUtils.assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        /*if (!(taraSession.getAllowedAuthMethods().contains(AuthenticationType.EIDAS) ||
                taraSession.getAllowedAuthMethods().contains(AuthenticationType.EIDAS_ONLY))) {
            throw new BadRequestException(INVALID_REQUEST, "Eidas authentication method is not allowed");
        }*/
    }

    @Data
    public static class Credential {
        @NotNull(message = "{message.eidas.invalid-country}")
        private String country;
    }

}
