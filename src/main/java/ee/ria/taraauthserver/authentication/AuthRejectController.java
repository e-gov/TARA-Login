package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;

@Slf4j
@Validated
@Controller
public class AuthRejectController {

    @Autowired
    AuthConfigurationProperties configurationProperties;

    @Autowired
    RestTemplate hydraService;

    @PostMapping("/auth/reject")
    public RedirectView authReject(@RequestParam(name = "error_code")
                                   @Pattern(regexp = "(user_cancel)", message = "the only supported value is: 'user_cancel'")
                                           String errorCode) {
        return rejectLogin(errorCode);
    }

    @NotNull
    private RedirectView rejectLogin(String errorCode) {
        TaraSession taraSession = SessionUtils.getAuthSession();
        var response = hydraService.exchange(
                getRequestUrl(taraSession.getLoginRequestInfo().getChallenge()),
                HttpMethod.PUT,
                createRequestBody(errorCode),
                Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
            taraSession.setState(AUTHENTICATION_CANCELED);
            SessionUtils.updateSession(taraSession);
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
    private HttpEntity<Map<String, String>> createRequestBody(String errorCode) {
        Map<String, String> map = new HashMap<>();
        map.put("error", errorCode);
        map.put("error_debug", "tekst");
        map.put("error_description", "tekst");
        return new HttpEntity<>(map);
    }

}
