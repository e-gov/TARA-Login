package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.FlowType;
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
import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
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
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertStatisticsIsNotLogged();
    }

    @Test
    void authReject_invalidParameter() {
        String sessionId = createSession();
        given()
                .when()
                .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
                .param("error_code", "wrongValue")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authReject.errorCode: the only supported value is: 'user_cancel'"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authReject.errorCode: the only supported value is: 'user_cancel'");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR, smartIdFlowType=null)");
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
        stubLoginReject(200, "mock_responses/mockLoginAcceptResponse.json");
        String sessionId = createSession();

        given()
                .when()
                .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
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
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"/some/test/url\"}");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED",
                defaultStatisticsMarkerBuilder()
                        .sector("public")
                        .authenticationState(AUTHENTICATION_CANCELED)
                        .build());
    }

    @Test
    void authReject_oidcRespondsWithError() {
        stubLoginReject(400, "mock_responses/incorrectMockLoginAcceptResponse.json");
        String sessionId = createSession();

        given()
                .when()
                .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .body("reportable", equalTo(true))
                .statusCode(500);

        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "TARA_HYDRA response: 400", "http.response.status_code=400, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .sector("public")
                        .authenticationState(AUTHENTICATION_FAILED)
                        .errorCode(INTERNAL_ERROR)
                        .build());
    }

    @Test
    void authReject_redirectUrlMissing() {
        stubLoginReject(200, "mock_responses/incorrectMockLoginAcceptResponse.json");
        String sessionId = createSession();

        given()
                .when()
                .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .body("reportable", equalTo(true))
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .sector("public")
                        .authenticationState(AUTHENTICATION_FAILED)
                        .errorCode(INTERNAL_ERROR)
                        .build());
    }

    @Test
    @Tag(value = "AUTH_REJECT_HYDRA_FAILURE")
    void authReject_hydraRequestFails() {
        stubLoginReject(200, "mock_responses/incorrectMockLoginAcceptResponse.json");
        String sessionId = createSession();

        given()
            .when()
            .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
            .param("error_code", "user_cancel")
            .get("/auth/reject")
            .then()
            .assertThat()
            .statusCode(500)
            .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
            .body("error", equalTo("Internal Server Error"))
            .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                .sector("public")
                .authenticationState(AUTHENTICATION_FAILED)
                .errorCode(INTERNAL_ERROR)
                .build());
    }

    @Test
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authReject_sidQrCodeSession_success() {
        stubLoginReject(200, "mock_responses/mockLoginAcceptResponse.json");
        String sessionId = createSession(FlowType.QR);

        given()
                .when()
                .sessionId(TARA_SESSION_COOKIE_NAME, sessionId)
                .param("error_code", "user_cancel")
                .get("/auth/reject")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("State: NOT_SET -> AUTHENTICATION_CANCELED");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED", 
                defaultStatisticsMarkerBuilder()
                        .sector("public")
                        .authenticationState(AUTHENTICATION_CANCELED)
                        .smartIdFlowType(FlowType.QR)
                        .build());
    }

    private void stubLoginReject(int status, String bodyFile) {
        wireMockServer.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile(bodyFile)));
    }

    @NotNull
    private String createSession() {
        return createSession(null);
    }

    @NotNull
    private String createSession(FlowType smartIdFlowType) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        lri.setChallenge(MOCK_LOGIN_CHALLENGE);
        lri.getClient().getMetaData().getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        authSession.setLoginRequestInfo(lri);
        authSession.setSmartIdFlowType(smartIdFlowType);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }

}
