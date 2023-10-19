package ee.ria.taraauthserver.authentication.webauthn;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.WebauthnConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.authentication.consent.AcceptConsentRequest;
import org.springframework.session.SessionRepository;
import org.springframework.session.Session;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;  
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.core.ParameterizedTypeReference;

import javax.cache.Cache;
import javax.validation.ConstraintViolation;
import javax.validation.Valid;
import javax.validation.Validator;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.WEBAUTHN_AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.WEBAUTHN_INTERNAL_ERROR;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_TOKEN_ATTR_NAME;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_WEBAUTHN_RESPONSE;
import static net.logstash.logback.argument.StructuredArguments.value;
import static java.util.Objects.requireNonNull;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.webauthn.enabled")
public class WebauthnCallbackController {
    public static final String WEBAUTHN_LOGIN_CALLBACK_REQUEST_MAPPING = "/auth/webauthn/login_callback";
    public static final String WEBAUTHN_REGISTER_CALLBACK_REQUEST_MAPPING = "/auth/webauthn/register_callback";
    public static final String VERIFICATION_FAILED = "Verification failed";
    public static final String REDIRECT_TO = "redirect_to";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.EEID, this.getClass());

    @Autowired
    private WebauthnConfigurationProperties webauthnConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private RestTemplate eeidRestTemplate;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private Cache<String, String> webauthnRelayStateCache;

    @Autowired
    private Validator validator;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @PostMapping(value = WEBAUTHN_LOGIN_CALLBACK_REQUEST_MAPPING)
    public ModelAndView webauthnLoginCallback(@RequestParam(name = "WebauthnResponse") String webauthnResponse,
                                              @RequestParam(name = "RelayState") String relayState) {
        log.info("Handling Webauthn authentication callback for relay state: {}", value("tara.session.webauthn.relay_state", relayState));
        if (!webauthnRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(webauthnRelayStateCache.getAndRemove(relayState));
        validateSession(session);

        try {
            String requestUrl = webauthnConfigurationProperties.getClientUrl() + "/webauthn/credential_authentication/return";

            requestLogger.logRequest(requestUrl, HttpMethod.POST, Map.of("webauthn_response", webauthnResponse));
            var response = eeidRestTemplate.exchange(
                    requestUrl,
                    HttpMethod.POST,
                    createRequestEntity(webauthnResponse),
                    WebauthnClientResponse.class);

            requestLogger.logResponse(response);

            WebauthnClientResponse webauthnClientResponse = response.getBody();
            validateResponse(webauthnClientResponse);
            updateSession(session, webauthnClientResponse);
        } catch (RestClientException e) {
            throw new ServiceNotAvailableException(WEBAUTHN_INTERNAL_ERROR, "Webauthn service error: " + e.getMessage(), e);
        }

        CsrfToken csrf = session.getAttribute(CSRF_TOKEN_ATTR_NAME);
        return new ModelAndView("webauthn", Map.of("token", csrf.getToken()));
    }

    @PostMapping(value = WEBAUTHN_REGISTER_CALLBACK_REQUEST_MAPPING)
    public String webauthnRegisterCallback(@RequestParam(name = "WebauthnResponse") String webauthnResponse,
                                           @RequestParam(name = "RelayState") String relayState) {
        log.info("Handling Webauthn registration callback for relay state: {}", value("tara.session.webauthn.relay_state", relayState));
        if (!webauthnRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(webauthnRelayStateCache.getAndRemove(relayState));
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        
        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        SessionUtils.assertSessionInState(taraSession, WAITING_WEBAUTHN_RESPONSE);

        AcceptConsentRequest acceptConsentRequest = AcceptConsentRequest.buildWithTaraSession(taraSession);
        String requestUrl = authConfigurationProperties.getHydraService().getAcceptConsentUrl() + "?consent_challenge=" + taraSession.getConsentChallenge();
        return getRedirectView(taraSession, requestUrl, acceptConsentRequest);
    }

    private String getRedirectView(TaraSession taraSession, String requestUrl, Object requestBody) {
        requestLogger.logRequest(requestUrl, HttpMethod.PUT, requestBody);
        var response = eeidRestTemplate.exchange(
                requestUrl,
                HttpMethod.PUT,
                new HttpEntity<>(requestBody),
                new ParameterizedTypeReference<Map<String, String>>() {
                });
        requestLogger.logResponse(response);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get(REDIRECT_TO) != null) {
            statisticsLogger.log(taraSession);
            SessionUtils.invalidateSession();
            return "redirect:" + response.getBody().get(REDIRECT_TO);
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

    private void handle422Exception(HttpClientErrorException.UnprocessableEntity e) {
        if (e.getMessage() != null && e.getMessage().contains(VERIFICATION_FAILED))
            throw new BadRequestException(WEBAUTHN_AUTHENTICATION_FAILED, e.getMessage(), e);
        else
            throw new BadRequestException(ERROR_GENERAL, e.getMessage(), e);
    }

    private void validateResponse(WebauthnClientResponse response) {
        Set<ConstraintViolation<WebauthnClientResponse>> constraintViolations = validator.validate(response);
        if (!constraintViolations.isEmpty()) {
            throw new IllegalStateException(getConstraintViolationsAsString(constraintViolations));
        }
    }

    private static String getConstraintViolationsAsString(Set<? extends ConstraintViolation<?>> constraintViolations) {
        return constraintViolations.stream()
                .map(cv -> cv == null ? "null" : cv.getPropertyPath() + ": " + cv.getMessage())
                .sorted().collect(Collectors.joining(", "));
    }

    private void updateSession(Session session, WebauthnClientResponse response) {
        if (response == null) {
            throw new IllegalStateException("Response body from Webauthn client is null.");
        }
        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        taraSession.setState(WEBAUTHN_AUTHENTICATION_COMPLETED);
        TaraSession.WebauthnAuthenticationResult authenticationResult = new TaraSession.WebauthnAuthenticationResult();
        String dateOfBirth = response.getAttributes().getDateOfBirth();
        authenticationResult.setFirstName(response.getAttributes().getFirstName());
        authenticationResult.setLastName(response.getAttributes().getFamilyName());
        authenticationResult.setPhoneNumber(response.getAttributes().getPhoneNumber());
        authenticationResult.setEmail(response.getAttributes().getEmail());
        if (dateOfBirth != null)
            authenticationResult.setDateOfBirth(LocalDate.parse(dateOfBirth));
        authenticationResult.setAcr(webauthnConfigurationProperties.getLevelOfAssurance());
        authenticationResult.setAmr(AuthenticationType.WEBAUTHN);
        authenticationResult.setSubject(response.getAttributes().getPersonIdentifier());
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private HttpEntity<MultiValueMap<String, String>> createRequestEntity(String webauthnResponse) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("webauthn_response", webauthnResponse);
        return new HttpEntity<>(map, headers);
    }

    public void validateSession(Session session) {
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");

        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        SessionUtils.assertSessionInState(taraSession, WAITING_WEBAUTHN_RESPONSE);
        if (((TaraSession.WebauthnAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState() == null) {
            throw new BadRequestException(ERROR_GENERAL, "Relay state is missing from session.");
        }
    }

     @Data
    private static class WebauthnClientResponse implements Serializable {
        @NotNull
        @Valid
        @JsonProperty("attributes")
        private Attributes attributes;
    }

    @Data
    private static class Attributes implements Serializable {
        @NotBlank
        @JsonProperty("given_name")
        private String FirstName;
        @NotBlank
        @JsonProperty("family_name")
        private String FamilyName;
        @NotBlank
        @JsonProperty("subject")
        private String PersonIdentifier;
        @JsonProperty("date_of_birth")
        private String DateOfBirth;
        @JsonProperty("phone_number")
        private String PhoneNumber;
        @JsonProperty("email")
        private String Email;
    }
}
