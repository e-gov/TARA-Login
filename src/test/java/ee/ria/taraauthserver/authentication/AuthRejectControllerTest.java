package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.ObjectFieldsAppendingMarker;
import org.hamcrest.Matchers;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Slf4j
class AuthRejectControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    void authReject_missingSession() {
        given()
                .when()
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));
    }

    @Test
    void authReject_invalidParameter() {
        given()
                .when()
                .param("error_code", "wrongValue")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authReject.errorCode: the only supported value is: 'user_cancel'"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: authReject.errorCode: the only supported value is: 'user_cancel'");
    }

    @Test
    void authReject_multipleParameters() {
        given()
                .when()
                .param("error_code", "wrongValue")
                .param("error_code", "wrongValue2")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Multiple request parameters with the same name not allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: error_code");
    }

    @Test
    void authReject_success() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        String sessionId = createSession();

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("OIDC login reject request: https://localhost:9877/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC");
        assertInfoIsLogged("Tara session state change: NOT_SET -> AUTHENTICATION_CANCELED");
        assertWarningIsLogged("Session has been invalidated: " + sessionId);
        assertInfoIsLogged("Session is removed from cache: " + sessionId);

        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLogged(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_CANCELED");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=null, idCode=null, ocspUrl=null, " +
                        "authenticationType=null, authenticationState=AUTHENTICATION_CANCELED, errorCode=null)",
                statisticsMarker.toStringSelf());
    }

    @Test
    void authReject_oidcRespondsWithError() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        String sessionId = createSession();

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .statusCode(500);

        assertErrorIsLogged("HTTP client exception: 400 Bad Request: [{}]");
    }

    @Test
    void authReject_redirectUrlMissing() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        String sessionId = createSession();

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
    }

    @NotNull
    private String createSession() {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        lri.setChallenge(MOCK_LOGIN_CHALLENGE);
        authSession.setLoginRequestInfo(lri);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }

}