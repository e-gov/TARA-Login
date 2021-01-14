package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
public class AuthAcceptControllerTest extends BaseTest {

    @Test
    @Tag("CSRF_PROTCTION")
    void authAccept_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(403)
                .body("message", equalTo("Forbidden"))
                .body("path", equalTo("/auth/accept"));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_missingSession() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_incorrectSessionState() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(INIT_AUTH_PROCESS)
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED]");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_OidcServerInvalidResponse_BadRequest() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("HTTP client exception");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_OidcServerInvalidResponse_MissingRedirectUrl() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_NaturalPersonAuthenticationComplete_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));
    }

    @Test
    @Tag(value = "AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_LegalPersonAuthenticationRequest_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("/auth/legalperson/init"));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_legalPersonAuthenticationComplete_Redirected() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_oidcServerTimeout() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_COMPLETED)
                        .requestedScopes(of("legalperson"))
                        .authenticationResult(MockTaraSessionBuilder.buildMockCredential())
                        .build())
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: I/O error on PUT request for \"https://localhost:9877/oauth2/auth/requests/login/accept\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
    }
}
