package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.MockSessionUtils.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Using MockMvc instead of RestAssuredMockMvc because of session mocking bug in RestAssured (see https://github.com/rest-assured/rest-assured/issues/780)

@Slf4j
public class AuthAcceptControllerTest extends BaseTest {

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_missingSession() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .when()
                .post("/auth/accept")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_incorrectSessionState() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.INIT_AUTH_PROCESS, getMockCredential());

        ResultActions resultActions = mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mockMvc)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request - invalid session.")))
                .andExpect(jsonPath("$.path", is("/auth/accept")));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: [LEGAL_PERSON_AUTHENTICATION_COMPLETED, NATURAL_PERSON_AUTHENTICATION_COMPLETED]");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_OidcServerInvalidResponse_BadRequest() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        ResultActions resultActions = mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mockMvc)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.")))
                .andExpect(jsonPath("$.path", is("/auth/accept")));

        assertErrorIsLogged("HTTP client exception");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_OidcServerInvalidResponse_MissingRedirectUrl() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        ResultActions resultActions = mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mockMvc)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.")))
                .andExpect(jsonPath("$.path", is("/auth/accept")));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_NaturalPersonAuthenticationComplete_Redirected() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockHttpSession testSession = MockSessionUtils.getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept")
                .session(testSession))
                .andDo(print())
                .andExpect(status().is(302))
                .andExpect(header().string("Location", "some/test/url"));
    }

    @Test
    @Tag(value = "AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_LegalPersonAuthenticationRequest_Redirected() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockHttpSession testSession = MockSessionUtils.getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        ((TaraSession) testSession.getAttribute(TARA_SESSION)).getLoginRequestInfo().setRequestedScopes(List.of("legalperson"));

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept")
                .session(testSession))
                .andDo(print())
                .andExpect(status().is(302))
                .andExpect(header().string("Location", "/auth/legal_person/init"));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    @Tag(value = "AUTH_ACCEPT_LOGIN_ENDPOINT")
    void authAccept_legalPersonAuthenticationComplete_Redirected() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockHttpSession testSession = MockSessionUtils.getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED);
        ((TaraSession) testSession.getAttribute(TARA_SESSION)).getLoginRequestInfo().setRequestedScopes(List.of("legalperson"));

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept")
                .session(testSession))
                .andDo(print())
                .andExpect(status().is(302))
                .andExpect(header().string("Location", "some/test/url"));
    }

    @Test
    @Tag(value = "ACCEPT_LOGIN")
    void authAccept_oidcServerTimeout() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockHttpSession testSession = MockSessionUtils.getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED);
        ((TaraSession) testSession.getAttribute(TARA_SESSION)).getLoginRequestInfo().setRequestedScopes(List.of("legalperson"));

        mockMvc.perform(MockMvcRequestBuilders.post("/auth/accept")
                .session(testSession))
                .andDo(print())
                .andExpect(status().is(500));

        assertErrorIsLogged("Server encountered an unexpected error: I/O error on PUT request for \"https://localhost:9877/oauth2/auth/requests/login/accept\": Read timed out; nested exception is java.net.SocketTimeoutException: Read timed out");
    }
}
