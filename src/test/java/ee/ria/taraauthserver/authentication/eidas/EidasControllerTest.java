package ee.ria.taraauthserver.authentication.eidas;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
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

import java.util.Arrays;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EIDAS;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EIDAS_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.awaitility.Durations.TEN_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class EidasControllerTest extends BaseTest {

    @Autowired
    EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private Cache<String, String> eidasRelayStateCache;

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_session_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam("country", "CA")
                .when()
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_session_status_incorrect() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EIDAS))
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
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_request_form_parameter_missing() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'country' is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Required String parameter 'country' is not present");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_REQUEST_CHECKS")
    void eidasAuthInit_request_country_not_supported() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EIDAS))
                        .authenticationState(INIT_AUTH_PROCESS)
                        .clientAllowedScopes(Arrays.asList("eidas")).build())
                .when()
                .formParam("country", "EE")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Antud riigikood ei ole lubatud. Lubatud riigikoodid on: CA"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Requested country not supported.");
    }

    @Test
    @DirtiesContext
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_timeout_responds_with_500() {

        EidasConfigurationProperties testConfig = new EidasConfigurationProperties();
        testConfig.setRequestTimeoutInSeconds(1);

        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        wireMockServer.stubFor(any(urlPathMatching("/login"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withFixedDelay((eidasConfigurationProperties.getRequestTimeoutInSeconds() * 1000) + 100)
                        .withBodyFile("mock_responses/eidas/eidas-login-response.json")));

        await().atMost(FIVE_SECONDS)
                .until(() -> eidasConfigurationProperties.getAvailableCountries().size(), Matchers.equalTo(1));

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationState(INIT_AUTH_PROCESS)
                .clientAllowedScopes(Arrays.asList("eidas")).build();
        given()
                .filter(sessionFilter)
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: I/O error on GET request for \"https://localhost:9877/login\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_request_successful() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 200);

        RestAssured.responseSpecification = null;

        await().atMost(FIVE_SECONDS)
                .until(() -> eidasConfigurationProperties.getAvailableCountries().size(), Matchers.equalTo(1));

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationState(INIT_AUTH_PROCESS)
                .clientAllowedScopes(Arrays.asList("eidas")).build();
        given()
                .filter(sessionFilter)
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        String relayState = ((TaraSession.EidasAuthenticationResult) taraSession.getAuthenticationResult()).getRelayState();
        assertEquals(WAITING_EIDAS_RESPONSE, taraSession.getState());
        assertEquals("CA", (taraSession.getAuthenticationResult()).getCountry());
        assertEquals(eidasRelayStateCache.get(relayState), sessionFilter.getSession().getId());
    }

    @Test
    @Tag(value = "EIDAS_AUTH_INIT_GET_REQUEST")
    void eidasAuthInit_request_unsuccessful() {
        createEidasCountryStub("mock_responses/eidas/eidas-response.json", 200);
        createEidasLoginStub("mock_responses/eidas/eidas-login-response.json", 400);

        await().atMost(TEN_SECONDS)
                .until(() -> eidasConfigurationProperties.getAvailableCountries().size(), Matchers.equalTo(1));

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EIDAS))
                .authenticationState(INIT_AUTH_PROCESS)
                .clientAllowedScopes(Arrays.asList("eidas")).build();
        given()
                .filter(sessionFilter)
                .when()
                .param("country", "CA")
                .post("/auth/eidas/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("Server encountered an unexpected error: 400 Bad Request:");
    }

    public static void createEidasCountryStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/supportedCountries"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    public static void createEidasLoginStub(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/login"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

}
