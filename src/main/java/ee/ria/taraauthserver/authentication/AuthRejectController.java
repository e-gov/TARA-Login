package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;

public class AuthRejectController {

    @Autowired
    AuthConfigurationProperties configurationProperties;

    @Autowired
    RestTemplate hydraService;

    @PostMapping("/auth/reject")
    public RedirectView authReject(@RequestParam(name = "error_code")
                                   @Pattern(regexp = "(user_cancel)", message = "The only supported value is: 'user_cancel'")
                                           String errorCode) {
        return rejectConsent(errorCode);
    }

    @NotNull
    private RedirectView rejectConsent(String errorCode) {
        TaraSession taraSession = SessionUtils.getAuthSession();
        String url = configurationProperties.getHydraService().getRejectLoginUrl() + "?login_challenge=" + taraSession.getLoginRequestInfo().getChallenge();
        Map<String, String> map = new HashMap<>();
        map.put("error", errorCode);
        map.put("error_debug", "Consent not given. User canceled the authentication process.");
        map.put("error_description", "Consent not given. User canceled the authentication process.");
        HttpEntity<Map> entity = new HttpEntity<>(map);
        ResponseEntity<Map> response = hydraService.exchange(url, HttpMethod.PUT, entity, Map.class);
        if (response.getStatusCode() == HttpStatus.OK && response.getBody().get("redirect_to") != null) {
            taraSession.setState(AUTHENTICATION_CANCELED);
            SessionUtils.updateSession(taraSession);
            return new RedirectView(response.getBody().get("redirect_to").toString());
        } else {
            throw new IllegalStateException("Invalid OIDC server response. Redirect URL missing from response.");
        }
    }

}
