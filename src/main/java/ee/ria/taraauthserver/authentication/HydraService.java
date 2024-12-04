package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.TaraSession;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.validation.constraints.NotNull;
import java.util.Map;

@Service
public class HydraService {

  private final ClientRequestLogger requestLogger = new ClientRequestLogger(ClientRequestLogger.Service.TARA_HYDRA,
      this.getClass());

  private final RestTemplate hydraRestTemplate;
  private final AuthConfigurationProperties configurationProperties;

  public HydraService(
      RestTemplate hydraRestTemplate,
      AuthConfigurationProperties configurationProperties) {
    this.hydraRestTemplate = hydraRestTemplate;
    this.configurationProperties = configurationProperties;
  }

  @NotNull
  public String rejectLogin(String errorCode, TaraSession taraSession) {
    String url = getRequestUrl(taraSession.getLoginRequestInfo().getChallenge());
    Map<String, String> requestBody = createRequestBody(errorCode);

    requestLogger.logRequest(url, HttpMethod.PUT, requestBody);
    var response = hydraRestTemplate.exchange(
        url,
        HttpMethod.PUT,
        new HttpEntity<>(requestBody),
        Map.class);
    requestLogger.logResponse(response);

    var responseBody = response.getBody();
    if (response.getStatusCode() != HttpStatus.OK || responseBody == null || responseBody.get("redirect_to") == null) {
      throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
    }
    return responseBody.get("redirect_to").toString();
  }

  @NotNull
  private String getRequestUrl(String loginChallenge) {
    return configurationProperties.getHydraService().getRejectLoginUrl() + "?login_challenge=" + loginChallenge;
  }

  @NotNull
  private Map<String, String> createRequestBody(String errorCode) {
    return Map.of(
        "error", errorCode,
        "error_debug", "User canceled the authentication process.",
        "error_description", "User canceled the authentication process.");
  }
}