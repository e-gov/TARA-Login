package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.LevelOfAssurance;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static java.lang.Integer.parseInt;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
public class AuthAcceptControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";


    @Test
    void authAccept_wrongOidcServerResponseCode() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        AuthSession testSession = createTestSession();

        mock.perform(MockMvcRequestBuilders.get("/auth/accept")
                .sessionAttr("session", testSession))
                .andDo(print())
                .andExpect(status().is(500));
    }

    @Test
    void authAccept_missingRedirectUrl() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        AuthSession testSession = createTestSession();

        mock.perform(MockMvcRequestBuilders.get("/auth/accept")
                .sessionAttr("session", testSession))
                .andDo(print())
                .andExpect(status().is(500));
    }

    @Test
    void authAccept_missingSession() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .when()
                .get("/auth/accept")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Something went wrong internally. Please consult server logs for further details."));
    }

    @Test
    void authAccept_incorrectSession() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        AuthSession testSession = createTestSession();
        testSession.setState(AuthState.INIT_AUTH_PROCESS);

        MvcResult result = mock.perform(MockMvcRequestBuilders.get("/auth/accept")
                .sessionAttr("session", testSession))
                .andDo(print())
                .andExpect(status().is(400))
                .andReturn();

        assertEquals("Authentication state must be AUTHENTICATION_SUCCESS", result.getResolvedException().getMessage());
    }


    // Using MockMvc instead of RestAssuredMockMvc because of session mocking bug in RestAssured (see https://github.com/rest-assured/rest-assured/issues/780)

    @Test
    void authAccept_isSuccessful() throws Exception {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        AuthSession testSession = createTestSession();

        mock.perform(MockMvcRequestBuilders.get("/auth/accept")
                .sessionAttr("session", testSession))
                .andDo(print())
                .andExpect(status().is(302));
    }

    private AuthSession createTestSession() {
        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.AUTHENTICATION_SUCCESS);
        AuthSession.AuthenticationResult authResult = new AuthSession.AuthenticationResult();
        authResult.setAcr(LevelOfAssurance.HIGH);
        testSession.setAuthenticationResult(authResult);

        AuthSession.LoginRequestInfo loginRequestInfo = new AuthSession.LoginRequestInfo();
        loginRequestInfo.setChallenge(TEST_LOGIN_CHALLENGE);
        testSession.setLoginRequestInfo(loginRequestInfo);
        return testSession;
    }
}
