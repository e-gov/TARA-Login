package ee.ria.taraauthserver.govsso;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

import static java.util.Objects.requireNonNull;

@Slf4j
@Component
@RequiredArgsConstructor
public class GovssoService {

    private final ClientRequestLogger requestLogger =
            new ClientRequestLogger(ClientRequestLogger.Service.GOVSSO_HYDRA, this.getClass());

    private final AuthConfigurationProperties.GovSsoHydraConfigurationProperties govSsoHydraConfigurationProperties;
    private final RestTemplate hydraRestTemplate;

    public boolean isGovssoClient(String clientId) {
        String govssoClientId = govSsoHydraConfigurationProperties.getClientId();
        if(StringUtils.isBlank(govssoClientId)) {
            return false;
        }
        return govssoClientId.equals(clientId);
    }

    public TaraSession.LoginRequestInfo fetchGovSsoLoginRequestInfo(String ssoChallenge) {
        URI requestUrl;
        try {
            requestUrl = new URIBuilder(govSsoHydraConfigurationProperties.getLoginUrl())
                    .addParameter("login_challenge", ssoChallenge)
                    .build();
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Unable to build GovSSO login URL", e);
        }
        try {
            requestLogger.logRequest(requestUrl.toString(), HttpMethod.GET);
            var response = hydraRestTemplate.exchange(
                    requestUrl,
                    HttpMethod.GET,
                    null,
                    TaraSession.LoginRequestInfo.class);
            requestLogger.logResponse(response);
            TaraSession.LoginRequestInfo responseBody = requireNonNull(response.getBody());
            if (!responseBody.getChallenge().equals(ssoChallenge)) {
                throw new IllegalStateException("Invalid GovSSO Hydra response: requested login_challenge does not match retrieved login_challenge");
            }

            return responseBody;
        } catch (HttpClientErrorException.NotFound | HttpClientErrorException.Gone e) {
            throw new NotFoundException("Login challenge not found.");
        }
    }

}
