package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.ObjectFieldsAppendingMarker;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpHeaders;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class AuthAcceptControllerTest extends BaseTest {

    @Test
    @Tag("CSRF_PROTCTION")
    void authAccept_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_missingSession() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_incorrectSessionState() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(INIT_AUTH_PROCESS)
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [AUTHENTICATION_SUCCESS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED]");
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, ERROR, "Authentication result: AUTHENTICATION_FAILED");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, " +
                        "ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)",
                statisticsMarker.toStringSelf());
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authAccept_OidcServerInvalidResponse_BadRequest() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("HTTP client exception");
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, ERROR, "Authentication result: AUTHENTICATION_FAILED");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, " +
                        "ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)",
                statisticsMarker.toStringSelf());
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

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, ERROR, "Authentication result: AUTHENTICATION_FAILED");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, " +
                        "ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)",
                statisticsMarker.toStringSelf());
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

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_SUCCESS");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, " +
                        "ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, errorCode=null)",
                statisticsMarker.toStringSelf());
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

        MockSessionFilter sessionFilter = withTaraSession()
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
        assertInfoIsLogged("OIDC login accept request for challenge: abcdefg098AAdsCC",
                "Tara session state change: NATURAL_PERSON_AUTHENTICATION_COMPLETED -> AUTHENTICATION_SUCCESS");

        assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_SUCCESS");

        resetMockLogAppender();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertMessageIsNotLogged(StatisticsLogger.class, "Authentication result: AUTHENTICATION_SUCCESS");
    }

    @Test
    @Tag(value = "AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_LegalPersonAuthenticationRequest_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
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

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));
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

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: I/O error on PUT request for \"https://localhost:9877/oauth2/auth/requests/login/accept\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, ERROR, "Authentication result: AUTHENTICATION_FAILED");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, " +
                        "ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)",
                statisticsMarker.toStringSelf());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_sessionStatusIsCanceled_Redirected(TaraAuthenticationState state) {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(state)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("http://localhost:"+port+"/auth/init?login_challenge=abcdefg098AAdsCC"));
    }
}
