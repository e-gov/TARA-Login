package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
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
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.regex.Pattern;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthInitControllerTest extends BaseTest {
    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";
    private static final String TEST_GOVSSO_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private static final Map<SPType, Map<String, List<String>>> AVAILABLE_COUNTRIES = Map.of(
            SPType.PUBLIC, Map.of("CA", new ArrayList<>(List.of("eidas"))),
            SPType.PRIVATE, Map.of("IT", new ArrayList<>(List.of("eidas")))
    );

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertStatisticsIsNotLogged();
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
                .body("message", equalTo("Required request parameter 'login_challenge' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Required request parameter 'login_challenge' for method parameter type String is not present");
        assertStatisticsIsNotLogged();
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authInit.loginChallenge: only characters and numbers allowed");
        assertStatisticsIsNotLogged();
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authInit.loginChallenge: size must be between 0 and 50");
        assertStatisticsIsNotLogged();
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertStatisticsIsNotLogged();
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertStatisticsIsNotLogged();
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
                .body(containsString("Sisestage ID-kaart kaardilugejasse ja vajutage \"Jätka\""))
                .body(not(containsString("src=\"data:image/svg+xml;base64")))
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
        assertEquals("test client et", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations().get("et"));
        assertEquals("testRelyingPartyName", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyName());
        assertEquals("testRelyingPartyId123", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyUuid());
        assertEquals(false, taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getShouldUseAdditionalVerificationCodeCheck());
        assertInfoIsLogged("New authentication session",
                "TARA_HYDRA request",
                "TARA_HYDRA response: 200",
                "State: NOT_SET -> INIT_AUTH_PROCESS");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsNotLogged();
    }

    @SneakyThrows
    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    @Tag(value = "AUTH_INIT_GOVSSO_VIEW")
    void authInit_Ok_requestMadeFromGovSsoClient() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/govsso_mock_response.json")));

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .header(HttpHeaders.CONTENT_LANGUAGE, "et")
                .body(containsString("Sisestage ID-kaart kaardilugejasse ja vajutage \"Jätka\""))
                .body(containsString("src=\"data:image/svg+xml;base64,testLogo\""))
                .body(containsString("govsso test client et"))
                .cookie("SESSION", matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertEquals(TEST_LOGIN_CHALLENGE, taraSession.getLoginRequestInfo().getChallenge());
        assertEquals(new URL("https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et"), taraSession.getLoginRequestInfo().getUrl());
        assertEquals("govSsoClientId", taraSession.getLoginRequestInfo().getClient().getClientId());
        assertEquals("idcard mid", taraSession.getLoginRequestInfo().getClient().getScope());
        assertEquals("idcard", taraSession.getLoginRequestInfo().getRequestedScopes().get(0));
        assertEquals("mid", taraSession.getLoginRequestInfo().getRequestedScopes().get(1));
        assertEquals("test client et", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations().get("et"));
        assertEquals("govsso test client et", taraSession.getGovSsoLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations().get("et"));
        assertEquals("testRelyingPartyName", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyName());
        assertEquals("testRelyingPartyId123", taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getRelyingPartyUuid());
        assertEquals(false, taraSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getSmartIdSettings().getShouldUseAdditionalVerificationCodeCheck());
        assertInfoIsLogged("New authentication session",
                "TARA_HYDRA request",
                "TARA_HYDRA response: 200",
                "State: NOT_SET -> INIT_AUTH_PROCESS",
                "GOVSSO_HYDRA request",
                "GOVSSO_HYDRA response: 200");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "GOVSSO_HYDRA request", "http.request.method=GET, url.full=https://localhost:8877/oauth2/auth/requests/login?login_challenge=abcdeff098aadfccabcdeff098aadfcc");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "GOVSSO_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdeff098aadfccabcdeff098aadfcc\",\"client\":{\"client_id\":\"govSsoDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"logo\":\"[8] chars\",\"name_translations\":{\"en\":\"govsso test client en\",\"et\":\"govsso test client et\",\"ru\":\"govsso test client ru\"},\"short_name_translations\":{\"en\":\"govsso short test client en\",\"et\":\"govsso short test client et\",\"ru\":\"govsso short test client ru\"}}},\"scope\":\"mid idcard eidas\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Ru\",\"ET\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"openid\",\"mid\",\"idcard\",\"eidas\"]}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @DirtiesContext
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_configuredTimeoutFails() {
        AuthConfigurationProperties.HydraConfigurationProperties test = new AuthConfigurationProperties.HydraConfigurationProperties();
        test.setRequestTimeoutInSeconds(1);
        authConfigurationProperties.setHydraService(test); // TODO AUT-857
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
                .statusCode(502)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRequestInvalidResponse_MissingRegistryCode() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_nok_missing_registry_code.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid hydra response: client.metaData.oidcClient.institution.registryCode: must not be blank");
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
                .body(containsString("Sisestage ID-kaart kaardilugejasse ja vajutage \"Jätka\""));
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
                .body(containsString("Поместите ID-карту в считыватель и нажмите кнопку \"Продолжить\""));
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
                .body(containsString("Insert your ID-card into the card reader and click \"Continue\""));

        assertStatisticsIsNotLogged();
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
                .body(containsString("Sisestage oma isikukood ja telefoninumber ning vajutage \"Jätka\""));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_CONF")
    void authInit_IdCardDisabledInConfiguration() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-not-set.json")));
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setEnabled(false); // TODO AUT-857

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

        assertStatisticsIsNotLogged();
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

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_SCOPES")
    void authInit_OIDCRequestsScopeThatIsNotAllowedAndScopeThatIsNotsupported() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_scope-unknown.json")));
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.HIGH); // TODO AUT-857
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
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_AcrRequestedByOidcIsHigh() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.HIGH); // TODO AUT-857
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

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_AcrRequestedByOidcIsHigh_And_AuthTypeLevelOfAssuranceIsNull() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.HIGH); // TODO AUT-857
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(null);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Level of assurance must be configured for authentication method: mobile-id. Please check the application configuration.");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"mid idcard eidas\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Ru\",\"ET\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"openid\",\"mid\",\"idcard\",\"eidas\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INTERNAL_ERROR)");
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.LOW);  // TODO AUT-857
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_NoAcrRequestedByOidc() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_acr-not-set.json")));
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.ID_CARD).setLevelOfAssurance(LevelOfAssurance.LOW); // TODO AUT-857
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

        assertStatisticsIsNotLogged();
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
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.LOW);  // TODO AUT-857
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"idcard mid banklink\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"ldap\",\"banklink\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=NO_VALID_AUTHMETHODS_AVAILABLE)");
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Unsupported acr value requested by client: 'wrongvalue'");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"wrongvalue\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INTERNAL_ERROR)");
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Vigane päring. Päringu volituskood ei ole korrektne."))
                .body("reportable", equalTo(false));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRespondsWith410() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Vigane päring. Päringu volituskood ei ole korrektne."))
                .body("reportable", equalTo(false));

        assertStatisticsIsNotLogged();
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
                .statusCode(502)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_GovSsoOidcRespondsWith404() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("reportable", equalTo(false));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=govSsoClientId, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INVALID_GOVSSO_LOGIN_CHALLENGE)");
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_GovSsoOidcRespondsWith410() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("reportable", equalTo(false));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=govSsoClientId, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INVALID_GOVSSO_LOGIN_CHALLENGE)");
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_GovSsoOidcRespondsWith500() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=govSsoClientId, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_NoRequestedScope() {
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_no_requested_scope.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Päringus puudub scope parameeter."))
                .body("reportable", equalTo(true));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"mid idcard\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Et\",\"RU\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=null, errorCode=MISSING_SCOPE)");
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Server encountered an unexpected error: Invalid hydra response: client.scope: must not be blank");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_redirectToAuthEidasInit_and_uppercaseCountryCodeIsIgnored() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly.json")));

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .statusCode(200)
                .body(containsString("<input type=\"hidden\" name=\"country\" value=\"CA\"/>"))
                .body(containsString("Redirecting, please wait..."))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWhenRequestedCountryIsInvalid() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly_with_invalid_country.json")));

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .statusCode(200)
                .body(containsString("European Union member state's eID"))
                .body(containsString("<option value=\"CA\">Test (CA)</option>"))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWithCountriesListForPublicSector() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly_with_invalid_country.json")));
        String expectedCountriesRegex = ".*<select id=\"country-select\" name=\"country\" data-methods=\".*\">\\s*<option value=\"\">Select your country</option>\\s*<option value=\"CA\">Test \\(CA\\)</option>\\s*</select>.*";
        Pattern expectedCountriesPattern = Pattern.compile(expectedCountriesRegex, Pattern.DOTALL);

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .statusCode(200)
                .body(matchesPattern(expectedCountriesPattern))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWithCountriesListForPrivateSector() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly_with_invalid_country_private_sector.json")));
        String expectedCountriesRegex = ".*<select id=\"country-select\" name=\"country\" data-methods=\".*\">\\s*<option value=\"\">Select your country</option>\\s*<option value=\"IT\">Italy</option>\\s*</select>.*";
        Pattern expectedCountriesPattern = Pattern.compile(expectedCountriesRegex, Pattern.DOTALL);

        String sessionId = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .statusCode(200)
                .body(matchesPattern(expectedCountriesPattern))
                .extract().cookie("SESSION");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_govSsoLoginChallengeIsEmpty() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_response_nok_sso_challenge_empty.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Incorrect GovSSO login challenge format.");
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_govSsoLoginChallengeIsInvalid() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_response_nok_sso_challenge_invalid.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Incorrect GovSSO login challenge format.");
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_govSsoLoginChallengeIsTooLong() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_response_nok_sso_challenge_too_long.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Incorrect GovSSO login challenge format.");
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_govSsoLoginChallengeIsNull() {

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_response_nok_sso_challenge_null.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Vigane päring. GovSSO päringu volituskood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Incorrect GovSSO login challenge format.");
    }
}