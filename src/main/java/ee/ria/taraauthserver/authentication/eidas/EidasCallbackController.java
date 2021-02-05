package ee.ria.taraauthserver.authentication.eidas;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.EidasInternalException;
import ee.ria.taraauthserver.error.exceptions.UnauthorizedException;
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
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDate;

import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Controller
@ConditionalOnProperty(value = "tara.auth-methods.eidas.enabled", matchIfMissing = true)
public class EidasCallbackController {

    @Autowired
    RestTemplate restTemplate;
    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @PostMapping(value = "/auth/eidas/callback")
    public String eidasCallback(@Validated @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession, @RequestParam(name = "SAMLResponse") String samlResponse) {
        SessionUtils.assertSessionInState(taraSession, WAITING_EIDAS_RESPONSE);
        validateSession(taraSession);

        try {
            EidasClientResponse response = restTemplate.exchange(eidasConfigurationProperties.getClientUrl() + "/returnUrl", HttpMethod.POST, createRequestEntity(samlResponse), EidasClientResponse.class).getBody();
            log.info("received response from eidas client: " + response.toString());
            updateSession(taraSession, response);
        } catch (HttpClientErrorException.Unauthorized e) {
            log.info("Requesting personal data failed - " + e.getMessage());
            taraSession.setState(AUTHENTICATION_FAILED);
            throw new UnauthorizedException(ERROR_GENERAL, e.getMessage(), e);
        } catch (Exception e) {
            log.info("Requesting personal data failed - " + e.getMessage());
            taraSession.setState(AUTHENTICATION_FAILED);
            throw new EidasInternalException(ERROR_GENERAL, e.getMessage(), e);
        }

        return "forward:/auth/accept";
    }

    private void updateSession(TaraSession taraSession, EidasClientResponse response) {
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setFirstName(response.getAttributes().getFirstName());
        authenticationResult.setLastName(response.getAttributes().getFamilyName());
        authenticationResult.setIdCode(response.getAttributes().getPersonIdentifier());
        authenticationResult.setDateOfBirth(LocalDate.parse(response.getAttributes().getDateOfBirth()));
        authenticationResult.setAcr(LevelOfAssurance.findByFormalName(response.getLevelOfAssurance()));
        authenticationResult.setAmr(AuthenticationType.EIDAS);
        authenticationResult.setSubject(taraSession.getAuthenticationResult().getCountry() + response.getAttributes().getPersonIdentifier());
        taraSession.setAuthenticationResult(authenticationResult);
    }

    @org.jetbrains.annotations.NotNull
    private HttpEntity<MultiValueMap<String, String>> createRequestEntity(String samlResponse) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("SAMLResponse", samlResponse);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        return request;
    }

    public void validateSession(TaraSession taraSession) {
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
