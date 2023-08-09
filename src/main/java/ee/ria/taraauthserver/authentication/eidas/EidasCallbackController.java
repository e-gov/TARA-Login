package ee.ria.taraauthserver.authentication.eidas;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

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

import static ee.ria.taraauthserver.error.ErrorCode.EIDAS_AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.error.ErrorCode.EIDAS_INCORRECT_LOA;
import static ee.ria.taraauthserver.error.ErrorCode.EIDAS_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.EIDAS_USER_CONSENT_NOT_GIVEN;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_TOKEN_ATTR_NAME;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EIDAS_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
public class EidasCallbackController {
    public static final String EIDAS_CALLBACK_REQUEST_MAPPING = "/auth/eidas/callback";
    public static final Pattern VALID_PERSON_IDENTIFIER_PATTERN = Pattern.compile("^([A-Z]{2,2})\\/([A-Z]{2,2})\\/(.*)$");
    public static final String REQUEST_DENIED = "Request denied";
    public static final String AUTHN_FAILED = "Authentication failed";
    public static final String INCORRECT_LOA = "202019";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.EIDAS, this.getClass());

    @Autowired
    private RestTemplate eidasRestTemplate;

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    @Autowired
    private Validator validator;

    @GetMapping(value = EIDAS_CALLBACK_REQUEST_MAPPING)
    public ModelAndView eidasCallback(@RequestParam(name = "code") String code,
                                      @RequestParam(name = "relay_state") String relayState) {
        log.info("Handling EIDAS authentication callback for relay state: {}", value("tara.session.eidas.relay_state", relayState));
        if (!eidasRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(eidasRelayStateCache.getAndRemove(relayState)); // TODO AUT-854
        validateSession(session);

        try {
            String requestUrl = eidasConfigurationProperties.getClientUrl() + "/auth/eidas/return";
            TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));

            requestLogger.logRequest(requestUrl, HttpMethod.POST, Map.of("code", code));
            var response = eidasRestTemplate.exchange(
                    requestUrl,
                    HttpMethod.POST,
                    createRequestEntity(code, taraSession),
                    EidasClientResponse.class);
            requestLogger.logResponse(response);

            EidasClientResponse eidasClientResponse = response.getBody();
            validateResponse(eidasClientResponse);
            updateSession(session, eidasClientResponse);
        } catch (HttpClientErrorException.Unauthorized e) {
            handle401Exception(e);
        } catch (RestClientException e) {
            throw new ServiceNotAvailableException(EIDAS_INTERNAL_ERROR, "EIDAS service error: " + e.getMessage(), e);
        }

        CsrfToken csrf = session.getAttribute(CSRF_TOKEN_ATTR_NAME);
        return new ModelAndView("eidas", Map.of("token", csrf.getToken()));
    }

    private void handle401Exception(HttpClientErrorException.Unauthorized e) {
        if (e.getMessage() != null && e.getMessage().contains(AUTHN_FAILED))
            throw new BadRequestException(EIDAS_AUTHENTICATION_FAILED, e.getMessage(), e);
        else if (e.getMessage() != null && e.getMessage().contains(REQUEST_DENIED))
            throw new BadRequestException(EIDAS_USER_CONSENT_NOT_GIVEN, e.getMessage(), e);
        else if (e.getMessage() != null && e.getMessage().contains(INCORRECT_LOA))
            throw new BadRequestException(EIDAS_INCORRECT_LOA, e.getMessage(), e);
        else
            throw new BadRequestException(ERROR_GENERAL, e.getMessage(), e);
    }

    private void updateSession(Session session, EidasClientResponse response) {
        if (response == null) {
            throw new IllegalStateException("Response body from EIDAS client is null.");
        }

        String personIdentifier = response.getAttributes().getPersonIdentifier();
        String dateOfBirth = response.getAttributes().getDateOfBirth();
        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        TaraSession.AuthenticationResult authenticationResult = taraSession.getAuthenticationResult();
        if (authenticationResult.getCountry() == "EE") {
          Matcher personIdentifierMatcher = validatePersonIdentifier(personIdentifier);
          authenticationResult.setIdCode(getIdCodeFromPersonIdentifier(personIdentifierMatcher));
        }
        authenticationResult.setFirstName(response.getAttributes().getFirstName());
        authenticationResult.setLastName(response.getAttributes().getFamilyName());
        authenticationResult.setPhoneNumber(response.getAttributes().getPhoneNumber());
        authenticationResult.setEmail(response.getAttributes().getEmail());
        if (dateOfBirth != null)
            authenticationResult.setDateOfBirth(LocalDate.parse(dateOfBirth));
        authenticationResult.setAcr(LevelOfAssurance.findByFormalName(response.getLevelOfAssurance()));
        authenticationResult.setSubject(personIdentifier);
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void validateResponse(EidasClientResponse response) {
        Set<ConstraintViolation<EidasClientResponse>> constraintViolations = validator.validate(response);
        if (!constraintViolations.isEmpty()) {
            throw new IllegalStateException(getConstraintViolationsAsString(constraintViolations));
        }
    }

    private static String getConstraintViolationsAsString(Set<? extends ConstraintViolation<?>> constraintViolations) {
        return constraintViolations.stream()
                .map(cv -> cv == null ? "null" : cv.getPropertyPath() + ": " + cv.getMessage())
                .sorted().collect(Collectors.joining(", "));
    }

    private Matcher validatePersonIdentifier(String personIdentifier) {
        Matcher matcher = VALID_PERSON_IDENTIFIER_PATTERN.matcher(personIdentifier);
        if (matcher.matches())
            return matcher;
        else
            throw new BadRequestException(EIDAS_AUTHENTICATION_FAILED, "The person identifier has invalid format! <" + personIdentifier + ">");
    }

    private String getIdCodeFromPersonIdentifier(Matcher personIdentifierMatcher) {
        return personIdentifierMatcher.group(3);
    }

    private String getCountryCodeFromPersonIdentifier(Matcher personIdentifierMatcher) {
        return personIdentifierMatcher.group(1);
    }

    private HttpEntity<MultiValueMap<String, String>> createRequestEntity(String code, TaraSession taraSession) {
        TaraSession.EidasAuthenticationResult authenticationResult = (TaraSession.EidasAuthenticationResult) taraSession.getAuthenticationResult();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("code", code);
        map.add("country", authenticationResult.getCountry());
        map.add("method", authenticationResult.getAmr().getAmrName());
        return new HttpEntity<>(map, headers);
    }

    public void validateSession(Session session) {
        if (session == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }
        TaraSession taraSession = requireNonNull(session.getAttribute(TARA_SESSION));
        SessionUtils.assertSessionInState(taraSession, WAITING_EIDAS_RESPONSE);
        if (((TaraSession.EidasAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState() == null) {
            throw new BadRequestException(ERROR_GENERAL, "Relay state is missing from session.");
        }
    }

    @Data
    private static class EidasClientResponse implements Serializable {
        @NotBlank
        @JsonProperty("acr")
        private String levelOfAssurance;
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
