package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.authentication.eudi.eudiplo.api.AuthenticationApi;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.api.Oid4VpApi;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.api.SessionApi;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.api.VerifierApi;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.AuthorizationResponse;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.OfferResponse;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.PresentationRequest;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.PresentationRequest.ResponseTypeEnum;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.TokenResponse;
import ee.ria.taraauthserver.config.properties.EudiConfigurationProperties;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static ee.ria.taraauthserver.error.ErrorCode.EUDI_INTERNAL_ERROR;

/**
 * Client of the eudiplo management API, generated from {@code src/main/openapi/eudiplo-management-api.json}, and of the
 * wallet-facing response endpoint of the eudiplo protocol API, generated from
 * {@code src/main/openapi/eudiplo-protocol-api.json}. The OAuth2 client-credentials token of the management API is
 * cached, and a 401 triggers one re-acquisition and retry. The protocol API takes no access token.
 */
@Slf4j
public class EudiploClient {

    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final long TOKEN_REFRESH_MARGIN_SECONDS = 300;
    private static final long DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

    private final ClientRequestLogger requestLogger =
            new ClientRequestLogger(ClientRequestLogger.Service.EUDIPLO, this.getClass());
    private final AtomicReference<CachedAccessToken> cachedAccessToken = new AtomicReference<>();
    private final EudiConfigurationProperties eudiConfigurationProperties;
    private final Clock clock;
    private final Oid4VpApi oid4VpApi;
    private final AuthenticationApi authenticationApi;
    private final VerifierApi verifierApi;
    private final SessionApi sessionApi;

    public EudiploClient(@NonNull RestClient eudiploRestClient,
                         @NonNull EudiConfigurationProperties eudiConfigurationProperties,
                         @NonNull Clock clock) {
        this.eudiConfigurationProperties = eudiConfigurationProperties;
        this.clock = clock;
        RestClient restClient = eudiploRestClient.mutate()
                .baseUrl(baseUrl())
                // Only JSON is ever read. The offer operation also lists image/png, a QR code of the wallet link.
                .requestInterceptor((request, body, execution) -> {
                    request.getHeaders().setAccept(List.of(MediaType.APPLICATION_JSON));
                    return execution.execute(request, body);
                })
                .build();
        RestClient authenticatedRestClient = restClient.mutate()
                .requestInterceptor((request, body, execution) -> {
                    request.getHeaders().setBearerAuth(accessToken());
                    return execution.execute(request, body);
                })
                .build();
        this.authenticationApi = createClient(restClient, AuthenticationApi.class);
        this.oid4VpApi = createClient(restClient, Oid4VpApi.class);
        this.verifierApi = createClient(authenticatedRestClient, VerifierApi.class);
        this.sessionApi = createClient(authenticatedRestClient, SessionApi.class);
    }

    public OfferResponse createPresentationOffer(@NonNull String presentationConfigId, @NonNull String redirectUri) {
        return createOffer(new PresentationRequest(ResponseTypeEnum.URI, presentationConfigId).redirectUri(redirectUri));
    }

    public OfferResponse createDcApiPresentationOffer(@NonNull String presentationConfigId,
                                                      @NonNull String expectedOrigin) {
        return createOffer(new PresentationRequest(ResponseTypeEnum.DC_API, presentationConfigId)
                .expectedOrigin(expectedOrigin));
    }

    private OfferResponse createOffer(PresentationRequest request) {
        // The generated model presets the documented default. It is left out instead, so that eudiplo applies its own.
        request.setClientIdScheme(null);
        String url = url(VerifierApi.PATH_VERIFIER_OFFER_CONTROLLER_GET_OFFER);

        requestLogger.logRequest(url, HttpMethod.POST, request);
        ResponseEntity<OfferResponse> response = callAuthenticated(
                HttpMethod.POST, url, () -> verifierApi.verifierOfferControllerGetOffer(request));
        requestLogger.logResponse(response);

        OfferResponse body = response.getBody();
        if (body == null || body.getSession() == null || body.getSession().isBlank()) {
            throw new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                    "eudiplo did not return a presentation session id for presentation configuration "
                            + request.getRequestId(),
                    null);
        }
        return body;
    }

    /**
     * The returned session carries the presented PID claims and the response code, and its {@code toString()} prints
     * them: it must never be logged.
     */
    public EudiploSession getPresentationSession(@NonNull String presentationSessionId) {
        String url = url(SessionApi.PATH_SESSION_CONTROLLER_GET_SESSION, presentationSessionId);

        requestLogger.logRequest(url, HttpMethod.GET);
        ResponseEntity<EudiploSession> response = callAuthenticated(
                HttpMethod.GET, url, () -> sessionApi.sessionControllerGetSession(presentationSessionId));
        requestLogger.logResponse(response.getStatusCode().value());
        return requireStatus(response.getBody(), presentationSessionId);
    }

    /**
     * {@link #getPresentationSession} without logging the request, the response or an error response, for the status
     * poll of a waiting login, which reads the session about once a second.
     */
    public EudiploSession pollPresentationSession(@NonNull String presentationSessionId) {
        ResponseEntity<EudiploSession> response;
        try {
            response = withTokenRefresh(() -> sessionApi.sessionControllerGetSession(presentationSessionId));
        } catch (RestClientException e) {
            throw requestFailed(HttpMethod.GET,
                    url(SessionApi.PATH_SESSION_CONTROLLER_GET_SESSION, presentationSessionId), e);
        }
        return requireStatus(response.getBody(), presentationSessionId);
    }

    private static EudiploSession requireStatus(EudiploSession presentationSession, String presentationSessionId) {
        if (presentationSession == null || presentationSession.getStatus() == null) {
            throw new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                    "eudiplo did not return a status for presentation session " + presentationSessionId, null);
        }
        return presentationSession;
    }

    /**
     * @return {@code true} when eudiplo accepted the answer, {@code false} when it rejected it with a 4xx
     */
    public boolean submitWalletResponse(@NonNull WalletResponse walletResponse, @NonNull String walletNonce) {
        String url = url(Oid4VpApi.PATH_OID4VP_CONTROLLER_GET_RESPONSE, walletNonce);
        AuthorizationResponse authorizationResponse = new AuthorizationResponse()
                .response(walletResponse.response())
                .error(walletResponse.error());

        requestLogger.logRequest(url, HttpMethod.POST);
        try {
            ResponseEntity<?> response = oid4VpApi.oid4vpControllerGetResponse(walletNonce, authorizationResponse);
            requestLogger.logResponse(response.getStatusCode().value());
            return true;
        } catch (HttpClientErrorException e) {
            logErrorResponse(e);
            return false;
        } catch (RestClientException e) {
            throw serviceNotAvailable(HttpMethod.POST, url, e);
        }
    }

    private String accessToken() {
        CachedAccessToken cached = cachedAccessToken.get();
        if (cached != null && Instant.now(clock).isBefore(cached.refreshAt())) {
            return cached.accessToken();
        }
        return acquireAccessToken();
    }

    private String acquireAccessToken() {
        String url = url(AuthenticationApi.PATH_AUTH_CONTROLLER_GET_O_AUTH2_TOKEN);

        requestLogger.logRequest(url, HttpMethod.POST);
        ResponseEntity<TokenResponse> response;
        try {
            response = authenticationApi.authControllerGetOAuth2Token(
                    GRANT_TYPE_CLIENT_CREDENTIALS, eudiConfigurationProperties.getClientId(),
                    eudiConfigurationProperties.getClientSecret());
        } catch (RestClientException e) {
            throw serviceNotAvailable(HttpMethod.POST, url, e);
        }
        requestLogger.logResponse(response.getStatusCode().value());

        TokenResponse body = response.getBody();
        if (body == null || body.getAccessToken() == null || body.getAccessToken().isBlank()) {
            throw new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                    "eudiplo did not return an access token", null);
        }
        long expiresIn = body.getExpiresIn() == null ? 0 : body.getExpiresIn().longValue();
        long lifetimeSeconds = expiresIn > 0 ? expiresIn : DEFAULT_TOKEN_LIFETIME_SECONDS;
        // Refresh well before expiry, but never later than halfway through the lifetime of a short-lived token.
        long refreshAfterSeconds = Math.max(lifetimeSeconds - TOKEN_REFRESH_MARGIN_SECONDS, lifetimeSeconds / 2);
        Instant refreshAt = Instant.now(clock).plusSeconds(refreshAfterSeconds);
        cachedAccessToken.set(new CachedAccessToken(body.getAccessToken(), refreshAt));
        log.info("Acquired eudiplo access token for client {}, refreshing it in {} seconds",
                eudiConfigurationProperties.getClientId(), refreshAfterSeconds);
        return body.getAccessToken();
    }

    private <T> T callAuthenticated(HttpMethod method, String url, Supplier<T> call) {
        try {
            return withTokenRefresh(call);
        } catch (RestClientException e) {
            throw serviceNotAvailable(method, url, e);
        }
    }

    private <T> T withTokenRefresh(Supplier<T> call) {
        try {
            return call.get();
        } catch (HttpClientErrorException.Unauthorized e) {
            log.info("eudiplo rejected the cached access token, acquiring a new one");
            cachedAccessToken.set(null);
            return call.get();
        }
    }

    private ServiceNotAvailableException serviceNotAvailable(HttpMethod method, String url, RestClientException e) {
        if (e instanceof RestClientResponseException responseException) {
            logErrorResponse(responseException);
        }
        return requestFailed(method, url, e);
    }

    private static ServiceNotAvailableException requestFailed(HttpMethod method, String url, RestClientException e) {
        return new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                "eudiplo request %s %s failed: %s".formatted(method, url, e.getMessage()), e);
    }

    private void logErrorResponse(RestClientResponseException e) {
        String responseBody = e.getResponseBodyAsString();
        requestLogger.logResponse(e.getStatusCode().value(), responseBody.isEmpty() ? null : responseBody);
    }

    private String url(String path, Object... uriVariables) {
        return UriComponentsBuilder.fromUriString(baseUrl() + path).buildAndExpand(uriVariables).toUriString();
    }

    private String baseUrl() {
        String eudiploUrl = eudiConfigurationProperties.getEudiploUrl();
        return eudiploUrl.endsWith("/") ? eudiploUrl.substring(0, eudiploUrl.length() - 1) : eudiploUrl;
    }

    private static <S> S createClient(RestClient restClient, Class<S> serviceType) {
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(restClient))
                .build()
                .createClient(serviceType);
    }

    private record CachedAccessToken(String accessToken, Instant refreshAt) {
    }

}
