package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.validation.constraints.Pattern;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Validated
@Controller
public class AuthRejectController {
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.TARA_HYDRA, this.getClass());

    @Autowired
    private AuthConfigurationProperties configurationProperties;

    @Autowired
    private RestTemplate hydraRestTemplate;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @GetMapping("/auth/reject")
    public RedirectView authReject(@RequestParam(name = "error_code") @Pattern(regexp = "user_cancel", message = "the only supported value is: 'user_cancel'") String errorCode,
                                   @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }

        String url = getRequestUrl(taraSession.getLoginRequestInfo().getChallenge());
        Map<String, String> requestBody = createRequestBody(errorCode);

        requestLogger.logRequest(url, HttpMethod.PUT, requestBody);
        var response = hydraRestTemplate.exchange(
                url,
                HttpMethod.PUT,
                new HttpEntity<>(requestBody),
                Map.class);
        requestLogger.logResponse(response);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().get("redirect_to") != null) {
            taraSession.setState(AUTHENTICATION_CANCELED);
            statisticsLogger.log(taraSession);
            SessionUtils.invalidateSession();
            return new RedirectView(response.getBody().get("redirect_to").toString());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
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
