package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
class SmartIdControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    private static final String ID_CODE = "smartIdCode";
    private static final String ID_CODE_VALUE = "10101010005";

    @Test
    void smartIdTest() throws InterruptedException {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(20000);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        log.info("end result: ");
        log.info(taraSession.toString());
    }

    @Test
    @Tag("CSRF_PROTCTION")
    void sidAuthInit_NoCsrf() throws InterruptedException {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .body("message", equalTo("Forbidden"))
                .body("path", equalTo("/auth/sid/init"));
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_status_incorrect() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_MID).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_SmartIdNotAllowed() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Smart ID authentication method is not allowed");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_missing() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_blank() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalidLength() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "382929292911")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalid() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "31107s14721")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    void sidAuthInit_ok() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/mid/mid_poll_response.json", 401);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "60001019939")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);
    }

}