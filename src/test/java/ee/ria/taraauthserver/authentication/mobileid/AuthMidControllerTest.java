package ee.ria.taraauthserver.authentication.mobileid;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidHashType;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthMidControllerTest extends BaseTest {
    private final MidAuthenticationHashToSign MOCK_HASH_TO_SIGN = new MidAuthenticationHashToSign.MobileIdAuthenticationHashToSignBuilder()
            .withHashType(MidHashType.SHA512)
            .withHashInBase64("bT+0Fuuf0QChq/sYb+Nz8vhLE8n3gLeL/wOXKxxE4ao=").build();


    // TODO parameter names (idCode vs id_code)
    @SpyBean
    private AuthMidService authMidService;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @BeforeEach
    void beforeEach() {
        Mockito.doReturn(MOCK_HASH_TO_SIGN).when(authMidService).getAuthenticationHash();
    }

    @AfterEach
    void afterEach() {
        Mockito.reset(authMidService);
    }

    @Test
    @Tag("CSRF_PROTCTION")
    void midAuthInit_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    void midAuthInit_session_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    void midAuthInit_session_status_incorrect() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(TaraAuthenticationState.INIT_MID).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void nationalIdNumber_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void nationalIdNumber_blank() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumber_invalidLength() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "382929292911")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumber_invalid() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "31107114721")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void phoneNumber_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void phoneNumber_blank() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_invalid() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "123abc456def")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_tooShort() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "+12345")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_tooLong() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "000007669837468734593465")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumberinvalid_and_phoneNumberInvalid() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .formParam("idCode", "31107114721")
                .formParam("telephoneNumber", "123abc456def")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 2 errors");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    void midAuthInit_session_mid_not_allowed() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(ID_CARD))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Mobile-ID authentication method is not allowed");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    @Tag(value = "MID_AUTH_INIT_REQUEST")
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void phoneNumberAndIdCodeValid() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200);
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();
        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("60001019906", result.getIdCode());
        assertEquals("EE", result.getCountry());
        assertEquals("MARY ÄNN", result.getFirstName());
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", result.getLastName());
        assertEquals("+37200000266", result.getPhoneNumber());
        assertEquals("EE60001019906", result.getSubject());
        assertEquals("2000-01-01", result.getDateOfBirth().toString());
        assertEquals(MOBILE_ID, result.getAmr());
        assertEquals(LevelOfAssurance.HIGH, result.getAcr());

        assertInfoIsLogged("Initiating Mobile-ID authentication session");
        assertInfoIsLogged("Mobile-ID authentication process with MID session id de305d54-75b4-431b-adb2-eb6b9e546015 has been initiated");
        assertInfoIsLogged("Polling Mobile-ID authentication process with MID session id de305d54-75b4-431b-adb2-eb6b9e546015");
        assertInfoIsLogged("MID session id de305d54-75b4-431b-adb2-eb6b9e546015 authentication result: OK, status: COMPLETE");
    }

    @Test
    void midAuthInit_request_language_is_correct() {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
                .withRequestBody(matchingJsonPath("$.language", WireMock.equalTo("ENG")))
                .willReturn(aResponse()
                        .withBodyFile("mock_responses/mid/mid_authenticate_response.json")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .when()
                .post("/auth/mid/init?lang=en")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_400() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 400);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during Mobile-ID authentication init: HTTP 400 Bad Request");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_401() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 401);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during Mobile-ID authentication init: Request is unauthorized for URI https://localhost:9877/mid-api/authentication: HTTP 401 Unauthorized");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_405() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 405);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during Mobile-ID authentication init: HTTP 405 Method Not Allowed");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_500() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 500);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: Mobile-ID service is currently unavailable: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
    }

    @Test
    void midAuthInit_response_no_certificate() { // TODO: no certificate?
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 500);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: Mobile-ID service is currently unavailable: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
    }


    @Test
    void midAuthInit_response_timeout() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200, 2000);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID)).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo("Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Service not available: Mobile-ID service is currently unavailable: java.net.SocketTimeoutException: Read timed out");
    }
}