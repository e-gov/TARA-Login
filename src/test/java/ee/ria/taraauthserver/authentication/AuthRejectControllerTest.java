package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static java.lang.String.format;

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
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertStatisticsIsNotLogged();
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
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authReject.errorCode: the only supported value is: 'user_cancel'");
        assertStatisticsIsNotLogged();
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
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: error_code");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
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
        assertInfoIsLogged("State: NOT_SET -> AUTHENTICATION_CANCELED");
        assertWarningIsLogged("Session has been invalidated: " + sessionId);
        assertInfoIsLogged("Session is removed from cache: " + sessionId);
        assertMessageWithMarkerIsLoggedOnce(AuthRejectController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthRejectController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_CANCELED, authenticationSessionId=null, errorCode=null)");
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
                .body("reportable", equalTo(true))
                .statusCode(500);

        assertMessageWithMarkerIsLoggedOnce(AuthRejectController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "TARA_HYDRA response: 400", "http.response.status_code=400, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INTERNAL_ERROR)");
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
                .body("reportable", equalTo(true))
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        assertMessageWithMarkerIsLoggedOnce(AuthRejectController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthRejectController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INTERNAL_ERROR)");
    }

    @NotNull
    private String createSession() {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        lri.setChallenge(MOCK_LOGIN_CHALLENGE);
        lri.getClient().getMetaData().getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        authSession.setLoginRequestInfo(lri);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }

}
