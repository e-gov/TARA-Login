package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.cache.Cache;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EIDAS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EidasCallbackControllerTest extends BaseTest {

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    private static final String MOCK_RELAY_STATE_VALUE = "abcdefg098AAdsCC";

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_missing() {
        eidasRelayStateCache.put(MOCK_RELAY_STATE_VALUE, "testSessionId123");

        given()
                .filter(MockSessionFilter.withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("SAMLResponse", "123test")
                .when()
                .formParam("RelayState", MOCK_RELAY_STATE_VALUE)
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
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
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [WAITING_EIDAS_RESPONSE]");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_status_missing_relayState() {

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EIDAS))
                        .authenticationResult(new TaraSession.EidasAuthenticationResult())
                        .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build())
                .formParam("SAMLResponse", "123test")
                .when()
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'RelayState' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User input exception: Required request parameter 'RelayState' for method parameter type String is not present");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_REQUEST_CHECKS")
    void eidasAuthCallback_session_status_missing_samlResponse() {

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EIDAS))
                        .authenticationResult(new TaraSession.EidasAuthenticationResult())
                        .authenticationState(TaraAuthenticationState.WAITING_EIDAS_RESPONSE).build())
                .when()
                .post("/auth/eidas/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'SAMLResponse' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User input exception: Required request parameter 'SAMLResponse' for method parameter type String is not present");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_200() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
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
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_missing_required_field_returns_500() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas-returnurl-response-missing-required-field.json", 200);

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

        assertErrorIsLogged("Server encountered an unexpected error: Unexpected error from eidas client: 500 Server Error:");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_401_authentication_failed() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
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
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_401_no_user_consent() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
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
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_response_404() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response.json", 404);

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
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"));

        assertWarningIsLogged("Session has been invalidated: " + sessionFilter.getSession().getId());
    }

    @Test
    @Tag(value = "EIDAS_AUTH_CALLBACK_RESPONSE_HANDLING")
    void eidasAuthCallback_returnUrl_doesnt_respond() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasReturnUrlStub("mock_responses/eidas/eidas-returnurl-response.json", 404, 2000);

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
    }

    protected static void createEidasCountryStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/supportedCountries"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
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
