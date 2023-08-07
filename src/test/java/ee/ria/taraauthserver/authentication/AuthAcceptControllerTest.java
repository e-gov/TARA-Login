package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpHeaders;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static java.lang.String.format;

@Slf4j
public class AuthAcceptControllerTest extends BaseTest {

    @Test
    @Tag("CSRF_PROTECTION")
    void authAccept_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag("ACCEPT_LOGIN")
    @Tag("CSRF_PROTECTION")
    void authAccept_session_missing() {
        given()
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_incorrectSessionState() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(INIT_AUTH_PROCESS)
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [AUTHENTICATION_SUCCESS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_OidcServerInvalidResponse_BadRequest() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("TARA_HYDRA response: 400");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "TARA_HYDRA response: 400", "http.response.status_code=400");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_OidcServerInvalidResponse_MissingRedirectUrl() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_NaturalPersonAuthenticationComplete_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, authenticationSessionId=%s, errorCode=null)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_AuthenticationSuccess_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertInfoIsLogged("State: NATURAL_PERSON_AUTHENTICATION_COMPLETED -> AUTHENTICATION_SUCCESS");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, authenticationSessionId=%s, errorCode=null)", sessionFilter.getSession().getId()));

        resetMockLogAppender();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertMessageIsNotLogged(AuthAcceptController.class, "TARA_HYDRA request");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_LegalPersonAuthenticationRequest_Redirected() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("/auth/legalperson/init"));

        assertMessageIsNotLogged(AuthAcceptController.class, "TARA_HYDRA request");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_legalPersonAuthenticationComplete_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                .requestedScopes(of("legalperson"))
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, authenticationSessionId=%s, errorCode=null)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_oidcServerTimeout() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                .requestedScopes(of("legalperson"))
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(502)
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: I/O error on PUT request for \"https://localhost:9877/oauth2/auth/requests/login/accept\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
        assertMessageWithMarkerIsLoggedOnce(AuthAcceptController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/accept?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"acr\":\"high\",\"amr\":[\"mID\"],\"remember\":false,\"subject\":\"EE47101010033\"}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_sessionStatusIsCanceled_Redirected(TaraAuthenticationState state) {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(state)
                .requestedScopes(of("legalperson"))
                .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("http://localhost:" + port + "/auth/init?login_challenge=abcdefg098AAdsCC"));

        assertMessageIsNotLogged(AuthAcceptController.class, "TARA_HYDRA request");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, subject=EE47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_CANCELED, authenticationSessionId=%s, errorCode=null)", sessionFilter.getSession().getId()));
    }
}