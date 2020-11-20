package ee.ria.taraauthserver.controllers;

import com.github.tomakehurst.wiremock.stubbing.StubMapping;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.config.LevelOfAssurance;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import javax.servlet.http.HttpSession;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.utils.Constants.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
class AuthInitControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Test
    void authInit_loginChallenge_EmptyValue() {
        given()
                .param("login_challenge", "")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    void authInit_loginChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'login_challenge' is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: Required String parameter 'login_challenge' is not present");
    }

    @Test
    void authInit_loginChallenge_InvalidValue() {
        given()
                .param("login_challenge", "......")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: authInit.loginChallenge: only characters and numbers allowed");
    }

    @Test
    void authInit_loginChallenge_InvalidLength() {
        given()
                .param("login_challenge", "123456789012345678901234567890123456789012345678900")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.loginChallenge: size must be between 0 and 50"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: authInit.loginChallenge: size must be between 0 and 50");
    }

    @Test
    void authInit_loginChallenge_DuplicatedParam() {
        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("login_challenge", "abcdefg098AAdsCCasassa")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Multiple request parameters with the same name not allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    void authInit_lang_InvalidValue() {
        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "est")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authInit.language: supported values are: 'et', 'en', 'ru'"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    void authInit_loginChallenge() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body("html.head.title", equalTo("Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"))
                .cookie("SESSION", matchesPattern("[A-Za-z0-9,-]{36,36}"));
    }

    @Test
    void authInit_Ok_session_status_is_correct() throws Exception {


        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        HttpSession result = mock.perform(MockMvcRequestBuilders.get("/auth/init").param("login_challenge", TEST_LOGIN_CHALLENGE))
                .andDo(print())
                .andExpect(status().is(200))
                .andExpect(request().sessionAttribute(TARA_SESSION, is(notNullValue())))
                .andReturn().getRequest().getSession();

        TaraSession taraSession = (TaraSession) result.getAttribute(TARA_SESSION);

        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
    }

    @Test
    @DirtiesContext
    void authInit_loginChallenge_configured_timeout_fails() {
        AuthConfigurationProperties.HydraConfigurationProperties test = new AuthConfigurationProperties.HydraConfigurationProperties();
        test.setRequestTimeoutInSeconds(1);
        authConfigurationProperties.setHydraService(test);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void authInit_loginChallengeInvalidResponse() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-nok_client_id-invalid.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void authInit_Ok_UiLocales_missing() throws Exception {
        StubMapping test = wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        log.info("is running? " + wireMockServer.isRunning());
        log.info("is running? " + wireMockServer.getSingleStubMapping(test.getUuid()).toString());

        mock.perform(MockMvcRequestBuilders.get("/auth/init").param("login_challenge", TEST_LOGIN_CHALLENGE))
                .andDo(print())
                .andExpect(status().is(200))
                .andExpect(content().string(containsString("Turvaline autentimine asutuste e-teenustes")))
                .andReturn();
    }

    @Test
    void authInit_Ok_Session_is_reset() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        String cookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .cookie("SESSION", matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie("SESSION");

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie("SESSION", cookie)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .cookie("SESSION", not(equalTo(cookie)));
    }

    @Test
    void authInit_Ok_uiLocales_ru() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        mock.perform(MockMvcRequestBuilders.get("/auth/init").param("login_challenge", TEST_LOGIN_CHALLENGE))
                .andDo(print())
                .andExpect(status().is(200))
                .andExpect(content().string(containsString("Для безопасной аутентификации в э-услугах")))
                .andReturn();
    }

    @Test
    void authInit_Ok_uiLocales_isOverridenByLangParameter() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        mock.perform(MockMvcRequestBuilders.get("/auth/init")
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "en"))
                .andDo(print())
                .andExpect(status().is(200))
                .andExpect(content().string(containsString("Secure authentication for e-services")))
                .andReturn();
    }

    @Test
    @DirtiesContext
    void authInit_Ok_uiLoales_incorrect() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-incorrect.json")));

        mock.perform(MockMvcRequestBuilders.get("/auth/init").param("login_challenge", TEST_LOGIN_CHALLENGE))
                .andDo(print())
                .andExpect(status().is(200))
                .andExpect(content().string(containsString("Turvaline autentimine asutuste e-teenustes")))
                .andReturn();
    }

    @Test
    void authInit_Ok_idcard_disabled() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.IDCard).setEnabled(false);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body(not(containsString("idCardForm")))
                .body(containsString("mobileIdForm"));
    }

    @Test
    void authInit_Ok_no_scopes_explicitly_requested_by_oidc_login_request() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body((containsString("mobileIdForm")))
                .body((containsString("idCardForm")));
    }

    @Test
    void authInit_Ok_LOW_acr_value_is_not_displayed() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.IDCard).setLevelOfAssurance(LevelOfAssurance.HIGH);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MobileID).setLevelOfAssurance(LevelOfAssurance.LOW);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body((containsString("idCardForm")))
                .body(not(containsString("mobileIdForm")));
    }

    @Test
    void authInit_Ok_no_acr_explicitly_requested_by_oidc_login_request() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_acr-not-set.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.IDCard).setLevelOfAssurance(LevelOfAssurance.LOW);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MobileID).setLevelOfAssurance(LevelOfAssurance.HIGH);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body(containsString("idCardForm"))
                .body(containsString("mobileIdForm"));

    }

    @Test
    void authInit_Ok_oidc_login_request_contains_invalid_scope() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_scope-unknown.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MobileID).setLevelOfAssurance(LevelOfAssurance.HIGH);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.IDCard).setLevelOfAssurance(LevelOfAssurance.HIGH);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE +
                        ";charset=UTF-8")
                .body(containsString("idCardForm"))
                .body(containsString("mobileIdForm"));

    }

    @Test
    void authInit_Nok_no_allowed_authmethods() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_scope-unknown.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MobileID).setLevelOfAssurance(LevelOfAssurance.LOW);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.IDCard).setLevelOfAssurance(LevelOfAssurance.LOW);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("message", equalTo("No authentication methods match the requested level of assurance. Please check your authorization request"))
                .body("error", equalTo("Bad Request"));

    }

    @Test
    void authInit_Nok_incorrect_acr_requested_by_oidc_login_request() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_acr-incorrect.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Server encountered an unexpected error: Unsupported acr value requested by client: 'wrongvalue'");
    }

    @Test
    void authInit_Nok_Oidc_server_404_response() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void authInit_Nok_Oidc_server_500_response() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void authInit_Nok_Oidc_server_response_invalid_parameters() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-nok_invalid_parameters.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

    }
}
