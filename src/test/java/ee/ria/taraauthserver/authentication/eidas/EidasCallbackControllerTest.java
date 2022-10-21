package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.cache.Cache;
import java.util.UUID;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EIDAS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static java.lang.String.format;

class EidasCallbackControllerTest extends BaseTest {

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    private static final String MOCK_RELAY_STATE_VALUE = "abcdefg098AAdsCC";

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_missing() {
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, "testSessionId123");

        given()
                .formParam("SAMLResponse", "123test")
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_status_incorrect() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationState(TaraAuthenticationState.INIT_MID).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .formParam("SAMLResponse", "123test")
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [WAITING_EIDAS_RESPONSE]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_status_missing_relayState() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(new TaraSession.EidasAuthenticationResult())
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        given()
                .filter(sessionFilter)
                .formParam("SAMLResponse", "123test")
                .when()
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'RelayState' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User input exception: Required request parameter 'RelayState' for method parameter type String is not present");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_status_missing_samlResponse() {
      MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(new TaraSession.EidasAuthenticationResult())
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'SAMLResponse' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User input exception: Required request parameter 'SAMLResponse' for method parameter type String is not present");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_200() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response.json", 200);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .redirects().follow(false)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertEquals(LevelOfAssurance.HIGH, (taraSession.getAuthenticationResult()).getAcr());
        assertEquals("Javier", (taraSession.getAuthenticationResult()).getFirstName());
        assertEquals("Garcia", (taraSession.getAuthenticationResult()).getLastName());
        assertEquals("12345", (taraSession.getAuthenticationResult()).getIdCode());
        assertEquals("CA12345", (taraSession.getAuthenticationResult()).getSubject());
        assertEquals("1965-01-01", (taraSession.getAuthenticationResult()).getDateOfBirth().toString());
        assertNull(eidasRelayStateCache.get(MOCK_RELAY_STATE_VALUE));
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS response: 200", "http.response.status_code=200, http.response.body.content={\"attributes\":{\"DateOfBirth\":\"1965-01-01\",\"FamilyName\":\"Garcia\",\"FirstName\":\"Javier\",\"PersonIdentifier\":\"CA/EE/12345\"},\"levelOfAssurance\":\"http://eidas.europa.eu/LoA/high\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_missing_required_field_returns_500() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response-missing-required-field.json", 200);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .redirects().follow(false)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"));

        assertErrorIsLogged("Server encountered an unexpected error: attributes.FamilyName: must not be blank");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS response: 200", "http.response.status_code=200, http.response.body.content={\"attributes\":{\"DateOfBirth\":\"1965-01-01\",\"FirstName\":\"Javier\",\"PersonIdentifier\":\"CA/EE/12345\"},\"levelOfAssurance\":\"http://eidas.europa.eu/LoA/high\"}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_401_authentication_failed() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response-401-auth-failed.json", 401);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("eIDAS autentimine ebaõnnestus."))
                .body("error", equalTo("Bad Request"));

        assertWarningIsLogged("Session has been invalidated: " + sessionFilter.getSession().getId());
        assertErrorIsLogged("User exception: 401 Unauthorized:");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "EIDAS response: 401", "http.response.status_code=401, http.response.body.content={\n" +
                "  \"error\": \"Unauthorized\",\n" +
                "  \"message\": \"Authentication failed\",\n" +
                "  \"status\": \"urn:oasis:names:tc:SAML:2.0:status:Responder\",\n" +
                "  \"subStatus\": \"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed\"\n" +
                "}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=EIDAS_AUTHENTICATION_FAILED)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_401_no_user_consent() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response-401-no-consent.json", 401);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Te keeldusite e-teenusele vajalike andmete edastamiseks nõusoleku andmisest."))
                .body("error", equalTo("Bad Request"));

        assertWarningIsLogged("Session has been invalidated: " + sessionFilter.getSession().getId());
        assertErrorIsLogged("User exception: 401 Unauthorized:");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "EIDAS response: 401", "http.response.status_code=401, http.response.body.content={\n" +
                "  \"error\": \"Unauthorized\",\n" +
                "  \"message\": \"Citizen consent not given.\",\n" +
                "  \"status\": \"urn:oasis:names:tc:SAML:2.0:status:Responder\",\n" +
                "  \"subStatus\": \"urn:oasis:names:tc:SAML:2.0:status:RequestDenied\"\n" +
                "}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=EIDAS_USER_CONSENT_NOT_GIVEN)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_404() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub(404);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo("eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Gateway"));

        assertErrorIsLogged("Service not available: EIDAS service error: 404 Not Found: [no body]");
        assertWarningIsLogged("Session has been invalidated: " + sessionFilter.getSession().getId());
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertMessageWithMarkerIsLoggedOnce(RestTemplateErrorLogger.class, ERROR, "EIDAS response: 404", "http.response.status_code=404");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=EIDAS_INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_doesnt_respond() {
        createEidasCountryStub("mock_responses/eidas/eidas-countries-response.json", 200);
        createEidasReturnUrlStub(404, 2000);
        TaraSession.EidasAuthenticationResult eidasAuthenticationResult = new TaraSession.EidasAuthenticationResult();
        eidasAuthenticationResult.setRelayState(UUID.randomUUID().toString());
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationResult(eidasAuthenticationResult)
                .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build();
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, sessionFilter.getSession().getId());

        given()
                .filter(sessionFilter)
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .formParam("SAMLResponse", "123test")
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo("eIDAS teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Gateway"));

        assertWarningIsLogged("Session has been invalidated: " + sessionFilter.getSession().getId());
        assertErrorIsLogged("Service not available: EIDAS service error: I/O error on POST request for \"https://localhost:9877/returnUrl\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
        assertMessageWithMarkerIsLoggedOnce(EidasCallbackController.class, INFO, "EIDAS request", "http.request.method=POST, url.full=https://localhost:9877/returnUrl, http.request.body.content={\"SAMLResponse\":\"123test\"}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=EIDAS_INTERNAL_ERROR)", sessionFilter.getSession().getId()));
    }

    protected static void createEidasCountryStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/supportedCountries"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    protected static void createEidasReturnUrlStub(int status) {
        createEidasReturnUrlStub(null, status, 0);
    }

    protected static void createEidasReturnUrlStub(int status, int delayInMilliseconds) {
        createEidasReturnUrlStub(null, status, delayInMilliseconds);
    }

    protected static void createEidasReturnUrlStub(String response, int status) {
        createEidasReturnUrlStub(response, status, 0);
    }

    protected static void createEidasReturnUrlStub(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathMatching("/returnUrl"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }
}
