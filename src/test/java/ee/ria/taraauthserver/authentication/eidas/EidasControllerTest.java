package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.OidcClient;
import io.restassured.RestAssured;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;

import javax.cache.Cache;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EIDAS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EIDAS_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.awaitility.Durations.TEN_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class EidasControllerTest extends BaseTest {
    private static final Map<SPType, List<String>> AVAILABLE_COUNTRIES = Map.of(
            SPType.PUBLIC, List.of("CA"),
            SPType.PRIVATE, List.of("IT")
    );

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_session_missing() {
        given()
                .filter(MockSessionFilter.withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("country", "CA")
                .when()
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_session_status_incorrect() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(List.of(EIDAS))
                        .authenticationState(TaraAuthenticationState.INIT_MID).build())
                .formParam("country", "CA")
                .when()
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_request_form_parameter_missing() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(List.of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'country' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Required request parameter 'country' for method parameter type String is not present");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_request_country_public_not_supported() {
        HashMap<SPType, List<String>> availableCountries = new HashMap<>(AVAILABLE_COUNTRIES);
        availableCountries.put(SPType.PUBLIC, List.of("CA", "LV", "LT"));
        eidasConfigurationProperties.setAvailableCountries(availableCountries); // TODO AUT-857
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(List.of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS)
                        .clientAllowedScopes(List.of("eidas")).build())
                .when()
                .formParam("country", "IT")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA, LV, LT"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Requested country not supported for public sector.");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=EIDAS_COUNTRY_NOT_SUPPORTED)");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_request_country_private_not_supported() {
        HashMap<SPType, List<String>> availableCountries = new HashMap<>(AVAILABLE_COUNTRIES);
        eidasConfigurationProperties.setAvailableCountries(availableCountries); // TODO AUT-857
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        MockSessionFilter taraSessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(List.of(EIDAS))
                .authenticationState(INIT_AUTH_PROCESS)
                .spType(SPType.PRIVATE)
                .clientAllowedScopes(List.of("eidas")).build();
        given()
                .filter(taraSessionFilter)
                .when()
                .formParam("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Antud riigikood ei ole lubatud. Lubatud riigikoodid on: IT"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Requested country not supported for private sector.");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=private, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=EIDAS_COUNTRY_NOT_SUPPORTED)");
    }

    @Test
    @DirtiesContext
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_timeout_responds_with_502() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES); // TODO AUT-857
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        wireMockServer.stubFor(any(urlPathMatching("/login"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withFixedDelay((eidasConfigurationProperties.getRequestTimeoutInSeconds() * 1000) + 100)
                        .withBodyFile("mock_responses/eidas/eidas-login-response.json")));

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(List.of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS)
                        .clientAllowedScopes(List.of("eidas")).build())
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: I/O error on GET request for \"https://localhost:9877/login\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
        assertMessageWithMarkerIsLoggedOnce(EidasController.class, INFO, "EIDAS request", "http.request.method=GET, url.full=https://localhost:9877/login?Country=CA&RequesterID=a:b:c&SPType=public&RelayState="); // Regex?
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_request_successful() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);
        RestAssured.responseSpecification = null;
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(List.of(EIDAS))
                .authenticationState(INIT_AUTH_PROCESS)
                .authenticationResult(new TaraSession.EidasAuthenticationResult())
                .clientAllowedScopes(List.of("eidas")).build();
        await().atMost(FIVE_SECONDS)
                .until(() -> eidasConfigurationProperties.getAvailableCountries().get(SPType.PUBLIC).size(), Matchers.equalTo(1)); // TODO AUT-857 Why is this needed? Side effect?

        given()
                .filter(sessionFilter)
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        OidcClient oidcClient = taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient();
        String relayState = ((TaraSession.EidasAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState();
        assertEquals(WAITING_EIDAS_RESPONSE, taraSession.getState());
        assertEquals("CA", (taraSession.getAuthenticationResult()).getCountry());
        assertEquals(eidasRelayStateCache.get(relayState), sessionFilter.getSession().getId());
        assertEquals("a:b:c", oidcClient.getEidasRequesterId().toString());
        assertEquals(SPType.PUBLIC, oidcClient.getInstitution().getSector());
        assertMessageWithMarkerIsLoggedOnce(EidasController.class, INFO, "EIDAS request", "http.request.method=GET, url.full=https://localhost:9877/login?Country=CA&RequesterID=a:b:c&SPType=public&RelayState="); // Regex?
        assertMessageWithMarkerIsLoggedOnce(EidasController.class, INFO, "EIDAS response: 200", "http.response.status_code=200, http.response.body.content=\"<html xmlns=\\\"http://www.w3.org/1999/xhtml\\\" xml:lang=\\\"en\\\"><body onload=\\\"document.forms[0].submit()\\\"><noscript><p><strong>Note: </strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p></noscript><form action=\\\"https&#x3a;&#x2f;&#x2f;eidastest.eesti.ee/&#x3a;8080&#x2f;EidasNode&#x2f;ServiceProvider\\\" method=\\\"post\\\"><div><input type=\\\"hidden\\\" name=\\\"SAMLRequest\\\" value=\\\"PD94bWw...........MnA6QXV0aG5SZXF1ZXN0Pg==\\\"/><input type=\\\"hidden\\\" name=\\\"country\\\" value=\\\"CA\\\"/></div><noscript><div><input type=\\\"submit\\\" value=\\\"Continue\\\"/></div></noscript></form></body></html>");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_request_unsuccessful() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasLoginStub(400);
        await().atMost(TEN_SECONDS)
                .until(() -> eidasConfigurationProperties.getAvailableCountries().get(SPType.PUBLIC).size(), Matchers.equalTo(1)); // TODO AUT-857 Why is this needed? Side effect?

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(List.of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS)
                        .clientAllowedScopes(List.of("eidas")).build())
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertMessageWithMarkerIsLoggedOnce(EidasController.class, INFO, "EIDAS request", "http.request.method=GET, url.full=https://localhost:9877/login?Country=CA&RequesterID=a:b:c&SPType=public&RelayState="); // Regex?
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "EIDAS response: 400", "http.response.status_code=400");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=openIdDemo, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    public static void createEidasCountryStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/supportedCountries"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    public static void createEidasLoginStub(int status) {
        createEidasLoginStub(null, status);
    }

    public static void createEidasLoginStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/login"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }
}
