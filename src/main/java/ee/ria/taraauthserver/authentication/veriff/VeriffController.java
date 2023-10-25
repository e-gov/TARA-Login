package ee.ria.taraauthserver.authentication.veriff;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.MediaType;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.authentication.mobileid.AuthMidController.MidRequest;
import ee.ria.taraauthserver.authentication.smartid.AuthSidService;
import ee.ria.taraauthserver.authentication.smartid.SmartIdController.SidCredential;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.VeriffConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import org.springframework.web.bind.annotation.RestController;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import org.springframework.web.client.RestClientException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.ResponseEntity;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.ConstraintViolation;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.io.Serializable;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.error.ErrorCode.VERIFF_INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_VERIFF_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;

@Slf4j
@Validated
@RestController
@ConditionalOnProperty(value = "tara.auth-methods.veriff.enabled")
public class VeriffController {
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.EEID, this.getClass());

    @Autowired
    private VeriffService veriffService;

    @Autowired
    private RestTemplate eeidRestTemplate;

    @Autowired
    private VeriffConfigurationProperties veriffConfigurationProperties;

    @PostMapping(value = "/auth/veriff/create", produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView veriffLogin(@Validated VeriffRequest veriffRequest, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Creating Veriff ID verification session for: " + veriffRequest.givenName + " " + veriffRequest.lastName);
        validateSession(taraSession, EnumSet.of(INIT_AUTH_PROCESS));

        try {
          String requestUrl = veriffConfigurationProperties.getClientUrl() + "/api/v1/veriff/sessions";

          requestLogger.logRequest(requestUrl, HttpMethod.POST, Map.of("givenName", veriffRequest.givenName, "lastName", veriffRequest.lastName));
          var response = eeidRestTemplate.exchange(
                  requestUrl,
                  HttpMethod.POST,
                  createRequestEntity(veriffRequest.givenName, veriffRequest.lastName, taraSession),
                  VeriffClientResponse.class);

          requestLogger.logResponse(response);

          VeriffClientResponse veriffClientResponse = response.getBody();
          updateSession(taraSession, veriffClientResponse);
      } catch (RestClientException e) {
          throw new ServiceNotAvailableException(VERIFF_INTERNAL_ERROR, "Veriff service error: " + e.getMessage(), e);
      }

      TaraSession.VeriffAuthenticationResult authenticationResult = (TaraSession.VeriffAuthenticationResult) taraSession.getAuthenticationResult();
      return new ModelAndView("veriff", Map.of("sessionUrl", authenticationResult.getVeriffSessionUrl(), "sessionId", authenticationResult.getVeriffSessionId()));
    }

    @PostMapping(value = "/auth/veriff/init")
    public ResponseEntity<Void> veriffInit(@RequestBody VeriffData data, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        log.info("Initiating Veriff ID verification session: " + data.getSessionId());
        validateSession(taraSession, EnumSet.of(WAITING_VERIFF_RESPONSE));
        veriffService.startVeriffSession(taraSession, data.getSessionId(), data.getSessionUrl());
        return ResponseEntity.ok().build();
    }

    private HttpEntity<MultiValueMap<String, String>> createRequestEntity(String givenName, String lastName, TaraSession taraSession) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("first_name", givenName);
        map.add("last_name", lastName);
        return new HttpEntity<>(map, headers);
    }

    public void validateSession(TaraSession taraSession, EnumSet<TaraAuthenticationState> validSessionStates) {
        SessionUtils.assertSessionInState(taraSession, validSessionStates);
        List<String> allowedScopes = getAllowedRequestedScopes(taraSession.getLoginRequestInfo());
        if (!(allowedScopes.contains("webauthn"))) {
            throw new BadRequestException(INVALID_REQUEST, "Webauthn scope is not allowed.");
        }
    }

    private void updateSession(TaraSession taraSession, VeriffClientResponse response) {
        if (response == null) {
            throw new IllegalStateException("Response body from Veriff client is null.");
        }

        TaraSession.VeriffAuthenticationResult authenticationResult = new TaraSession.VeriffAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.VERIFF);
        authenticationResult.setVeriffSessionId(response.getSessionId());
        authenticationResult.setVeriffSessionUrl(response.getSessionUrl());
        taraSession.setState(WAITING_VERIFF_RESPONSE);
        taraSession.setAuthenticationResult(authenticationResult);
    }

    private void handle401Exception(HttpClientErrorException.Unauthorized e) {
        throw new BadRequestException(ERROR_GENERAL, e.getMessage(), e);
    }

    @NotNull
    private List<String> getAllowedRequestedScopes(TaraSession.LoginRequestInfo loginRequestInfo) {
        return Arrays.asList(loginRequestInfo.getClient().getScope().split(" "));
    }

    @Data
    private static class VeriffClientResponse implements Serializable {
        @NotBlank
        @JsonProperty("session_url")
        private String sessionUrl;
        @NotBlank
        @JsonProperty("session_id")
        private String sessionId;
    }

    @Data
    public static class VeriffRequest {
        private String givenName;
        private String lastName;
        private String lang;
    }

    @Data
    static class VeriffData {
        private String sessionId;
        private String sessionUrl;
    }
}
