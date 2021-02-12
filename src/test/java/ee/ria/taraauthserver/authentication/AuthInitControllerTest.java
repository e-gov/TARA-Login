package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthInitControllerTest extends BaseTest {
    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
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
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);
    }

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
    void authInit_loginChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'login_challenge' is not present"))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Required String parameter 'login_challenge' is not present");
    }

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
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
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: authInit.loginChallenge: only characters and numbers allowed");
    }

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
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
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: authInit.loginChallenge: size must be between 0 and 50");
    }

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
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
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);
    }

    @Test
    @Tag(value = "AUTH_INIT_ENDPOINT")
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
                .body("incident_nr", notNullValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);
    }

    @SneakyThrows
    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_Ok() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .header(HttpHeaders.CONTENT_LANGUAGE, "et")
                .body("html.head.title", equalTo("Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"))
                .cookie("SESSION", matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertEquals(TEST_LOGIN_CHALLENGE, taraSession.getLoginRequestInfo().getChallenge());
        assertEquals(new URL("https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et"), taraSession.getLoginRequestInfo().getUrl());
        assertEquals("openIdDemo", taraSession.getLoginRequestInfo().getClient().getClientId());
        assertEquals("idcard mid", taraSession.getLoginRequestInfo().getClient().getScope());
        assertEquals("idcard", taraSession.getLoginRequestInfo().getRequestedScopes().get(0));
        assertEquals("mid", taraSession.getLoginRequestInfo().getRequestedScopes().get(1));
        assertEquals("some test client", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getName());
        assertEquals("testRelyingPartyName", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyName());
        assertEquals("testRelyingPartyId123", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyUuid());
        assertEquals(true, taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getShouldUseAdditionalVerificationCodeCheck());


        assertInfoIsLogged("OIDC login GET request: https://localhost:9877/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE);
        assertInfoIsLogged("OIDC login response Code: 200");
        assertInfoIsLogged("OIDC login response Body: TaraSession.LoginRequestInfo(challenge=abcdefg098AAdsCC, client=TaraSession.Client(clientId=openIdDemo, metaData=TaraSession.MetaData(oidcClient=TaraSession.OidcClient(name=some test client, nameTranslations={et=test client et, en=test client en, ru=test client ru}, shortName=stc, shortNameTranslations={et=short test client et, en=short test client en, ru=short test client ru}, legacyReturnUrl=null, institution=TaraSession.Institution(sector=public), smartIdSettings=TaraSession.SmartIdSettings(relyingPartyUuid=testRelyingPartyId123, relyingPartyName=testRelyingPartyName, ShouldUseAdditionalVerificationCodeCheck=true)), displayUserConsent=false), scope=idcard mid), requestedScopes=[idcard, mid], oidcContext=TaraSession.OidcContext(acrValues=[low], uiLocales=null), url=https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et)");
    }

    @Test
    @DirtiesContext
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_configuredTimeoutFails() {
        AuthConfigurationProperties.HydraConfigurationProperties test = new AuthConfigurationProperties.HydraConfigurationProperties();
        test.setRequestTimeoutInSeconds(1);
        authConfigurationProperties.setHydraService(test);

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay((authConfigurationProperties.getHydraService().getRequestTimeoutInSeconds() * 1000) + 100)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRequestInvalidResponse() {
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
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_SessionIsReset() {
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
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_OidcLocalemissing() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        given().param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_LANGUAGE, "et")
                .body("html.head.title", equalTo("Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"));
    }

    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_OidcLocaleIsRu() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given().param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_LANGUAGE, "ru")
                .body("html.head.title", equalTo("Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"));
    }

    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_OidcLocaleIsOverridenByLangParameter() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "en")
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_LANGUAGE, "en")
                .body("html.head.title", equalTo("National authentication service - Secure authentication for e-services"));
    }

    @Test
    @DirtiesContext
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_OidcLocaleIncorrect() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-incorrect.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_LANGUAGE, "et")
                .body("html.head.title", equalTo("Riigi autentimisteenus - Turvaline autentimine asutuste e-teenustes"));
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_CONF")
    void authInit_IdCardDisabledInConfiguration() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setEnabled(false);

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
    @Tag(value = "AUTH_INIT_DEFAULT_AUTHMETHODS_LIST")
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
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_SCOPES")
    void authInit_OIDCRequestsScopeThatIsNotAllowedAndScopeThatIsNotsupported() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_scope-unknown.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.HIGH);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.HIGH);

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
                .body(not(containsString("mobileIdForm")));

        assertWarningIsLogged("Requested scope value 'ldap' is not allowed, entry ignored!");
        assertWarningIsLogged("Unsupported scope value 'banklink', entry ignored!");
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_AcrRequestedByOidcIsHigh() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.HIGH);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.LOW);

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
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_NoAcrRequestedByOidc() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_acr-not-set.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.LOW);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.HIGH);

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
    @DirtiesContext
    @Tag(value = "AUTH_INIT_NO_VALID_AUTHMETHODS")
    void authInit_NoAllowedAuthMethods() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_scope-unknown.json")));

        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.LOW);
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.LOW);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8)
                .body("message", equalTo("Autentimispäring ei ole korrektne. Soovitud autentimistasemele vastavaid autentimisvahendeid pole antud infosüsteemile lubatud."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", notNullValue());

    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_IncorrectAcrRequestedByOidc() {
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
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Server encountered an unexpected error: Unsupported acr value requested by client: 'wrongvalue'");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRespondsWith404() {
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
                .statusCode(400)
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Vigane päring. Päringu volituskood ei ole korrektne."));
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRespondsWith500() {
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
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcResponseBodyContainsInvalidParameters() {
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
                .body("incident_nr", notNullValue())
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid hydra response: client.metaData.oidcClient.institution.sector: invalid sector value, accepted values are: private, public, client.metaData.oidcClient.shortName: size must be between 0 and 40, client.scope: must not be blank");
    }
}
