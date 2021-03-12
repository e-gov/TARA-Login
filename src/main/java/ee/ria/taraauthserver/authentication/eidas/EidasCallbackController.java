package ee.ria.taraauthserver.authentication.eidas;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.cache.Cache;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static co.elastic.apm.agent.shaded.bytebuddy.implementation.FixedValue.value;
import static ee.ria.taraauthserver.error.ErrorCode.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled")
public class EidasCallbackController {
    public static final String EIDAS_CALLBACK_REQUEST_MAPPING = "/auth/eidas/callback";

    public static final Pattern VALID_PERSON_IDENTIFIER_PATTERN = Pattern.compile("^([A-Z]{2,2})\\/([A-Z]{2,2})\\/(.*)$");

    @Autowired
    @Qualifier("eidasRestTemplate")
    private RestTemplate restTemplate;
    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;
    @Autowired
    private SessionRepository<Session> sessionRepository;
    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    @PostMapping(value = EIDAS_CALLBACK_REQUEST_MAPPING)
    public ModelAndView eidasCallback(@RequestParam(name = "SAMLResponse") String samlResponse, @RequestParam(name = "RelayState") String relayState) {

        if (!eidasRelayStateCache.containsKey(relayState))
            throw new BadRequestException(INVALID_REQUEST, "relayState not found in relayState map");

        Session session = sessionRepository.findById(eidasRelayStateCache.getAndRemove(relayState));
        validateSession(session);

        try {
            EidasClientResponse response = restTemplate.exchange(eidasConfigurationProperties.getClientUrl() + "/returnUrl", HttpMethod.POST, createRequestEntity(samlResponse), EidasClientResponse.class).getBody();
            if (response != null) {
                log.info("Received response from eidas client: {}", value(response));
                updateSession(session, response);
            } else {
                throw new IllegalStateException("Response body from eidas client is null.");
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            handle401Exception(session, e);
        } catch (ResourceAccessException e) {
            handleIOException(session, e);
        } catch (Exception e) {
            handleOtherExceptions(session, e);
        }

        CsrfToken csrf = session.getAttribute("tara.csrf");
        return new ModelAndView("eidas", Map.of("token", csrf.getToken()));
    }

    private void handleIOException(Session session, Exception e) {
        updateSession(session);
        throw new ServiceNotAvailableException(EIDAS_INTERNAL_ERROR, "Eidas service did not respond: " + e.getMessage(), e);
    }

    private void handleOtherExceptions(Session session, Exception e) {
        updateSession(session);
        throw new IllegalStateException("Unexpected error from eidas client: " + e.getMessage(), e);
    }

    private void handle401Exception(Session session, HttpClientErrorException.Unauthorized e) {
        updateSession(session);
        if (e.getMessage() != null && e.getMessage().contains("Authentication failed"))
            throw new BadRequestException(EIDAS_AUTHENTICATION_FAILED, e.getMessage(), e);
        else if (e.getMessage() != null && e.getMessage().contains("No user consent received. User denied access."))
            throw new BadRequestException(EIDAS_USER_CONSENT_NOT_GIVEN, e.getMessage(), e);
        else
            throw new BadRequestException(ERROR_GENERAL, e.getMessage(), e);
    }

    private void updateSession(Session session) {
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        taraSession.setState(AUTHENTICATION_FAILED);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void updateSession(Session session, EidasClientResponse response) {
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setFirstName(response.getAttributes().getFirstName());
        authenticationResult.setLastName(response.getAttributes().getFamilyName());
        authenticationResult.setIdCode(getFormattedPersonIdentifier(response.getAttributes().getPersonIdentifier()));
        authenticationResult.setDateOfBirth(LocalDate.parse(response.getAttributes().getDateOfBirth()));
        authenticationResult.setAcr(LevelOfAssurance.findByFormalName(response.getLevelOfAssurance()));
        authenticationResult.setAmr(AuthenticationType.EIDAS);
        authenticationResult.setSubject(taraSession.getAuthenticationResult().getCountry() + response.getAttributes().getPersonIdentifier());
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private String getFormattedPersonIdentifier(String personIdentifier) {
        Matcher matcher = VALID_PERSON_IDENTIFIER_PATTERN.matcher(personIdentifier);
        if (matcher.matches()) {
            return matcher.group(1) + matcher.group(3);
        } else {
            throw new BadRequestException(EIDAS_AUTHENTICATION_FAILED, "The person identifier has invalid format! <" + personIdentifier + ">");
        }
    }

    @org.jetbrains.annotations.NotNull
    private HttpEntity<MultiValueMap<String, String>> createRequestEntity(String samlResponse) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("SAMLResponse", samlResponse);
        return new HttpEntity<>(map, headers);
    }

    public void validateSession(Session session) {
        if (session == null)
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        log.info("AuthSession: {}", taraSession);
        SessionUtils.assertSessionInState(taraSession, WAITING_EIDAS_RESPONSE);
        if (((TaraSession.EidasAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState() == null) {
            throw new BadRequestException(ERROR_GENERAL, "Relay state is missing from session.");
        }
    }

    @Data
    private static class EidasClientResponse implements Serializable {
        @NotBlank
        @JsonProperty("levelOfAssurance")
        private String levelOfAssurance;
        @NotNull
        @Valid
        @JsonProperty("attributes")
        private Attributes attributes;

    }

    @Data
    private static class Attributes implements Serializable {
        @NotBlank
        @JsonProperty("FirstName")
        private String FirstName;
        @NotBlank
        @JsonProperty("FamilyName")
        private String FamilyName;
        @NotBlank
        @JsonProperty("PersonIdentifier")
        private String PersonIdentifier;
        @NotBlank
        @JsonProperty("DateOfBirth")
        private String DateOfBirth;
    }

}
