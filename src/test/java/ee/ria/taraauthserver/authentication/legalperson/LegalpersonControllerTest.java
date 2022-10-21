package ee.ria.taraauthserver.authentication.legalperson;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import io.restassured.path.json.JsonPath;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_CLIENT_ID;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockCredential;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.GET_LEGAL_PERSON_LIST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static java.lang.String.format;

@Slf4j
public class LegalpersonControllerTest extends BaseTest {

    public static final String MOCK_LEGAL_PERSON_IDENTIFIER = "ABC-00000000-_abc";
    public static final String MOCK_LEGAL_PERSON_NAME = "Acme & sons OÜ";

    @BeforeEach
    void beforeEach() {
        RestAssured.responseSpecification = null;
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPersonInit_noSession() {
        given()
                .when()
                .get("/auth/legalperson/init")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("path", equalTo("/auth/legalperson/init"));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPersonInit_invalidSessionStatus() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(INIT_AUTH_PROCESS)
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson/init")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("path", equalTo("/auth/legalperson/init"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [NATURAL_PERSON_AUTHENTICATION_COMPLETED]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPersonInit_invalidRequest_noLegalpersonScopeInOidcRequest() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .clientAllowedScopes(of("mid", "legalperson"))
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson/init")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("path", equalTo("/auth/legalperson/init"));

        assertErrorIsLogged("User exception: scope 'legalperson' was not requested in the initial OIDC authentication request");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INVALID_REQUEST)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPersonInit_invalidRequest_scopeNotAllowed() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                .clientAllowedScopes(of(""))
                .requestedScopes(of("mid", "legalperson"))
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson/init")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("path", equalTo("/auth/legalperson/init"));

        assertErrorIsLogged(String.format("User exception: client '%s' is not authorized to use scope 'legalperson'", MOCK_CLIENT_ID));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INVALID_REQUEST)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    @Tag(value = "UI_LEGALPERSON_AUTHENTICATION_VIEW")
    void getAuthLegalPersonInit_Ok() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(buildMockCredential())
                        .clientAllowedScopes(of("mid", "legalperson"))
                        .requestedScopes(of("mid", "legalperson"))
                        .build())
                .when()
                .get("/auth/legalperson/init")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .extract().response().htmlPath();

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPerson_noSession() {
        given()
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .header("Set-Cookie", nullValue())
                .body("status", equalTo(400))
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_AUTH_START")
    void getAuthLegalPerson_invalidSessionStatus() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(INIT_AUTH_PROCESS)
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [LEGAL_PERSON_AUTHENTICATION_INIT]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    void getAuthLegalPerson_xroadError_SoapFaultInResponse() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/nok-soapfault.xml")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                .authenticationResult(buildMockCredential())
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(500))
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("Server encountered an unexpected error: X-Road service returned a soap fault: faultcode = 'SOAP-ENV:Server', faultstring = 'Sisendparameetrid vigased: palun sisestage kas äriregistri kood, isikukood või isiku ees- ja perekonnanimi.'");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    void getAuthLegalPerson_xroadError_InvalidResponse() throws Exception {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "text/html; charset=UTF-8")
                        .withBody("Not found")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                .authenticationResult(buildMockCredential())
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(500))
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("Server encountered an unexpected error: Failed to extract data from response: https://localhost:9877/cgi-bin/consumer_proxy");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    void getAuthLegalPerson_xroadError_RequestTimesOut() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withFixedDelay(5000)
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                .authenticationResult(buildMockCredential())
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(502)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(502))
                .body("error", equalTo("Bad Gateway"))
                .body("message", equalTo("Äriregistriga ei saadud ühendust. Palun proovige hiljem uuesti."))
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("Service not available: Could not connect to business registry. Connection failed: Read timed out");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    void getAuthLegalPerson_noValidLegalPersonsFound() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-no-match.xml")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                .authenticationResult(buildMockCredential())
                .build();
        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(404)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(404))
                .body("error", equalTo("Not Found"))
                .body("message", equalTo("Current user has no valid legal person records in business registry")) // TODO: NotFoundException -> BadRequestException?
                .body("path", equalTo("/auth/legalperson"));

        assertErrorIsLogged("Results not found: Current user has no valid legal person records in business registry");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=47101010033, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    @Tag(value = "LEGAL_PERSON_AUTH_START_ENDPOINT")
    void getAuthLegalPerson_validLegalPersons_singleLegalPersonFound() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));

        JsonPath response = given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                        .authenticationResult(buildMockCredential())
                        .build())
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .extract().jsonPath();

        assertThat(response.getString("legalPersons[0].legalName")).isEqualTo("Acme INC OÜ");
        assertThat(response.getString("legalPersons[0].legalPersonIdentifier")).isEqualTo("12341234");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    @Tag(value = "LEGAL_PERSON_AUTH_START_ENDPOINT")
    void getAuthLegalPerson_validLegalPersons_multipleLegalPersonFound() throws Exception {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-multiple-matches.xml")));

        JsonPath response = given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                        .authenticationResult(buildMockCredential())
                        .build())
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .extract().jsonPath();

        assertThat(response.getString("legalPersons[0].legalName")).isEqualTo("Acme INC OÜ 1");
        assertThat(response.getString("legalPersons[0].legalPersonIdentifier")).isEqualTo("11111111");
        assertThat(response.getString("legalPersons[1].legalName")).isEqualTo("Acme INC UÜ 2");
        assertThat(response.getString("legalPersons[1].legalPersonIdentifier")).isEqualTo("22222222");
        assertThat(response.getString("legalPersons[2].legalName")).isEqualTo("Acme INC TÜ 3");
        assertThat(response.getString("legalPersons[2].legalPersonIdentifier")).isEqualTo("33333333");
        assertThat(response.getString("legalPersons[3].legalName")).isEqualTo("Acme INC AS 4");
        assertThat(response.getString("legalPersons[3].legalPersonIdentifier")).isEqualTo("44444444");
        assertThat(response.getString("legalPersons[4].legalName")).isEqualTo("Acme INC TÜH 5");
        assertThat(response.getString("legalPersons[4].legalPersonIdentifier")).isEqualTo("55555555");
        assertThat(response.getString("legalPersons[5].legalName")).isEqualTo("Acme INC SA 6");
        assertThat(response.getString("legalPersons[5].legalPersonIdentifier")).isEqualTo("66666666");
        assertThat(response.getString("legalPersons[6].legalName")).isEqualTo("Acme INC MTÜ 7");
        assertThat(response.getString("legalPersons[6].legalPersonIdentifier")).isEqualTo("77777777");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag("CSRF_PROTECTION")
    void postAuthLegalPersonConfirm_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .param("legal_person_identifier", "1234")
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    @Tag("CSRF_PROTECTION")
    void postAuthLegalPersonConfirm_session_missing() {
        given()
                .param("legal_person_identifier", "1234")
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    void postAuthLegalPersonConfirm_invalidSessionStatus() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                .build();
        given()
                .filter(sessionFilter)
                .param("legal_person_identifier", "1234")
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("path", equalTo("/auth/legalperson/confirm"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'LEGAL_PERSON_AUTHENTICATION_INIT', expected one of: [GET_LEGAL_PERSON_LIST]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_ENDPOINT")
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    void postAuthLegalPersonConfirm_MissingRequiredParam() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Required request parameter 'legal_person_identifier' for method parameter type String is not present"))
                .body("path", equalTo("/auth/legalperson/confirm"));

        assertErrorIsLogged("User input exception: Required request parameter 'legal_person_identifier' for method parameter type String is not present");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    void postAuthLegalPersonConfirm_InvalidParameter_InvalidInput() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build();
        given()
                .filter(sessionFilter)
                .param("legal_person_identifier", "<>?=`*,.")
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier"))
                .body("path", equalTo("/auth/legalperson/confirm"));

        assertErrorIsLogged("User input exception: confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    void postAuthLegalPersonConfirm_InvalidParameter_notListed() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(GET_LEGAL_PERSON_LIST)
                .legalPersonList(of(new TaraSession.LegalPerson("Acme OÜ", "123456abcd")))
                .build();
        given()
                .filter(sessionFilter)
                .param("legal_person_identifier", "9876543210")
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Antud identifikaatoriga juriidilist isikut ei leitud."))
                .body("path", equalTo("/auth/legalperson/confirm"));

        assertErrorIsLogged("User exception: Attempted to select invalid legal person with id: '9876543210'");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INVALID_LEGAL_PERSON)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "LEGAL_PERSON_SELECTION_CONFIRMED")
    @Tag(value = "LEGAL_PERSON_SELECTION_ENDPOINT")
    void postAuthLegalPersonConfirm_validLegalPersonIdentifier() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationState(GET_LEGAL_PERSON_LIST)
                .authenticationResult(buildMockCredential())
                .legalPersonList(of(new TaraSession.LegalPerson(MOCK_LEGAL_PERSON_NAME, MOCK_LEGAL_PERSON_IDENTIFIER)))
                .build();
        given()
                .filter(sessionFilter)
                .param("legal_person_identifier", MOCK_LEGAL_PERSON_IDENTIFIER)
                .when()
                .post("/auth/legalperson/confirm")
                .then()
                .assertThat()src/test/java/ee/ria/taraauthserver/authentication/legalperson/LegalpersonControllerTest.java
                .statusCode(302)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .header("Location", Matchers.endsWith("/some/test/url"));

        assertInfoIsLogged("Legal person confirmed");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=true, country=EE, idCode=ABC-00000000-_abc, firstName=Mari-Liis, lastName=Männik, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, authenticationSessionId=%s, errorCode=null)", sessionFilter.getSession().getId()));
    }
}
