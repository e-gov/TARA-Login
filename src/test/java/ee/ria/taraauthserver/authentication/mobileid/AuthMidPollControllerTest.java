package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import org.eclipse.jetty.server.Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthMidPollControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @BeforeEach
    void beforeEach() {
        RestAssured.responseSpecification = null;
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_VALID_SESSION")
    void midAuth_session_missing() {
        given()
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_HTML_RESPONSE_HEADERS)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_VALID_SESSION")
    void midAuth_session_status_incorrect() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_HTML_RESPONSE_HEADERS)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED, NATURAL_PERSON_AUTHENTICATION_COMPLETED]");
    }

    @Test
    @Tag(value = "MID_AUTH_PENDING")
    void midAuth_session_status_poll_mid_status() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(POLL_MID_STATUS).build())
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_JSON_RESPONSE_HEADERS)
                .body("status", equalTo("PENDING"));
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_ENDPOINT")
    @Tag(value = "MID_AUTH_SUCCESS")
    void midAuth_session_status_authentication_success() {
        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED).build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_JSON_RESPONSE_HEADERS)
                .body("status", equalTo("COMPLETED"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
    }

    @Test
    @Tag(value = "MID_AUTH_FAILED")
    void midAuth_session_status_authentication_error_general() {
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setErrorCode(ErrorCode.ERROR_GENERAL);

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(AUTHENTICATION_FAILED)
                .authenticationResult(authenticationResult).build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_HTML_RESPONSE_HEADERS)
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.ERROR_GENERAL, taraSession.getAuthenticationResult().getErrorCode());
    }

    @Test
    @Tag(value = "MID_AUTH_FAILED")
    void midAuth_session_status_authentication_mid_internal_error() {
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setErrorCode(ErrorCode.MID_INTERNAL_ERROR);

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(AUTHENTICATION_FAILED)
                .authenticationResult(authenticationResult).build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(502)
                .headers(EXPECTED_HTML_RESPONSE_HEADERS)
                .body("error", equalTo("Bad Gateway"))
                .body("message", equalTo("Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.MID_INTERNAL_ERROR, taraSession.getAuthenticationResult().getErrorCode());
    }
}