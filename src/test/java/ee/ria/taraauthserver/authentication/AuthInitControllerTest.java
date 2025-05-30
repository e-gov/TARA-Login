package ee.ria.taraauthserver.authentication;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.EidasConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.govsso.GovssoService;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URL;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class AuthInitControllerTest extends BaseTest {
    private static final String TEST_LOGIN_CHALLENGE = "abcdefg098AAdsCC";
    private static final String TEST_GOVSSO_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private static final Map<SPType, List<String>> AVAILABLE_COUNTRIES = Map.of(
            SPType.PUBLIC, List.of("CA"),
            SPType.PRIVATE, List.of("IT")
    );

    private static final String MOCK_RESPONSE_AUTH_FLOW_TIMEOUT = "{\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"dev-local-mock-cl ient\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"eidas_requester_id\":\"urn:uuid:99dc4792-cba5-11ec-a957-571ea9ac2691\",\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations \":{\"en\":\"Service name (dev-local)\",\"et\":\"Teenusenimi (dev-local)\",\"ru\":\"название службы (dev-local)\"},\"short_name_translations\":{\"en\":\"string_en\",\"et\":\"string_et\",\"ru\":\"string_ru\"},\"smartid_settings\":{\"should_u se_additional_verification_code_check\":true}}},\"scope\":\"openid eidas eidasonly eidas:country:* idcard mid smartid email phone legalperson\"},\"login_challenge_expired\":false,\"oidc_context\":{\"ui_locales\":[\"et\"]},\" request_url\":\"https://oidc-service.dev-local.riaint.ee:8443/oidc/authorize?scope=openid&response_type=code&client_id=dev-local-mock-client&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=1801fd6 8-ec16-4e98-9c98-6928806d08ee&nonce=c1214a17-de2d-4aab-be0a-480b261013e8&ui_locales=et\",\"requested_at\":%s,\"requested_scope\":[\"openid\"]}";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private EidasConfigurationProperties eidasConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties.GovSsoConfigurationProperties govSsoConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties.HydraConfigurationProperties hydraConfigurationProperties;

    @AfterEach
    void tearDown() {
        configurationPropertiesReloader.reload(authConfigurationProperties);
    }

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
    void nonExistingEndpoint_ReturnsHttp404() {
        given()
            .when()
            .get("/non-existing-endpoint")
            .then()
            .assertThat()
            .statusCode(404)
            .body("error", equalTo("Not Found"))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .body(not(containsString("class=\"detailed-instruction-line detailed-session-management\"")))
                .cookie(TARA_SESSION_COOKIE_NAME, matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

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
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsNotLogged();
    }


    @SneakyThrows
    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_VIEW")
    void authInit_Ok_veryLongBase64Icon() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/govsso_mock_response_longBase64Icon.json")));

        Path path = Path.of("src/test/resources/svg/mockLongIcon.svg");
        String originalString = Files.readString(path);
        String base64 =  Base64.getEncoder().encodeToString(originalString.getBytes());

        given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(200)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
            .header(HttpHeaders.CONTENT_LANGUAGE, "et")
            .body(containsString("src=\"data:image/svg+xml;base64,"+ base64 +"\""))
            .extract().cookie(TARA_SESSION_COOKIE_NAME);
    }

    @SneakyThrows
    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    @Tag(value = "AUTH_INIT_GOVSSO_VIEW")
    void authInit_Ok_requestMadeFromGovSsoClient() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
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
                .body(containsString("class=\"detailed-instruction-line detailed-session-management\""))
                .cookie(TARA_SESSION_COOKIE_NAME, matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

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
                "GOVSSO_HYDRA request",
                "GOVSSO_HYDRA response: 200",
                "State: NOT_SET -> INIT_AUTH_PROCESS"
        );
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(GovssoService.class, INFO, "GOVSSO_HYDRA request", "http.request.method=GET, url.full=https://localhost:8877/admin/oauth2/auth/requests/login?login_challenge=abcdeff098aadfccabcdeff098aadfcc");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertMessageWithMarkerIsLoggedOnce(GovssoService.class, INFO, "GOVSSO_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdeff098aadfccabcdeff098aadfcc\",\"client\":{\"client_id\":\"govSsoDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"logo\":\"[8] chars\",\"name_translations\":{\"en\":\"govsso test client en\",\"et\":\"govsso test client et\",\"ru\":\"govsso test client ru\"},\"short_name_translations\":{\"en\":\"govsso short test client en\",\"et\":\"govsso short test client et\",\"ru\":\"govsso short test client ru\"}}},\"scope\":\"mid idcard eidas\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Ru\",\"ET\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"openid\",\"mid\",\"idcard\",\"eidas\"]}");
        assertStatisticsIsNotLogged();
    }

    @SneakyThrows
    @ParameterizedTest
    @ValueSource(strings = {"et","en","ru"})
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    @Tag(value = "AUTH_INIT_GOVSSO_VIEW")
    void authInit_Ok_requestMadeFromGovSsoClient_allLanguages( String language) {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/govsso_mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/auth/init?lang=" + language)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .header(HttpHeaders.CONTENT_LANGUAGE, language)
                .body(containsString("class=\"detailed-instruction-line detailed-session-management\""))
                .body(containsString(govSsoConfigurationProperties.getSelfServiceUrl() + "?lang=" + language));
    }

    @Test
    @DirtiesContext
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_configuredTimeoutFails() {
        AuthConfigurationProperties.HydraConfigurationProperties test = new AuthConfigurationProperties.HydraConfigurationProperties();
        test.setLoginUrl(hydraConfigurationProperties.getLoginUrl());
        test.setRequestTimeoutInSeconds(1);
        authConfigurationProperties.setHydraService(test); // TODO AUT-857
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .cookie(TARA_SESSION_COOKIE_NAME, matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(TARA_SESSION_COOKIE_NAME, cookie)
                .when()
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .cookie(TARA_SESSION_COOKIE_NAME, not(equalTo(cookie)));

    }

    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_OidcLocalemissing() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
    void authInit_OidcLocaleIsOverriddenByLangParameter() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_WhenLocaleFromCookieIsOverriddenByHydra() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .get("/auth/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_LANGUAGE, "ru")
                .body(containsString("Поместите ID-карту в считыватель и нажмите кнопку \"Продолжить\""));

        assertStatisticsIsNotLogged();
    }


    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_WhenLocaleFromCookieAndHydraIsOverriddenByLangParam() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/mock_response.json")));

        given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .param("lang", "et")
            .when()
            .cookie("__Host-LOCALE", "en")
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(200)
            .header(HttpHeaders.CONTENT_LANGUAGE, "et")
            .body(containsString("Sisestage oma isikukood ja telefoninumber ning vajutage \"Jätka\""));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_WhenInvalidLocaleFromHydraIsOverriddenByCookie() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-incorrect.json")));

        given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .cookie("__Host-LOCALE", "en")
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(200)
            .header(HttpHeaders.CONTENT_LANGUAGE, "en")
            .body(containsString("Insert your ID-card into the card reader and click \"Continue\""));

        assertStatisticsIsNotLogged();
    }


    @Test
    @Tag(value = "AUTH_INIT_UI_LOCALE")
    void authInit_WhenInvalidLocaleFromHydraAndCookieIsOverriddenByDefault() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/mock_response-ok_ui_locales-incorrect.json")));

        given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .cookie("__Host-LOCALE", "fr")
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"mid idcard eidas\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Ru\",\"ET\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"openid\",\"mid\",\"idcard\",\"eidas\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
        authConfigurationProperties.getAuthMethods().get(AuthenticationType.MOBILE_ID).setLevelOfAssurance(LevelOfAssurance.LOW);  // TODO AUT-857
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_NoAcrRequestedByOidc() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .body("reportable", equalTo(false));

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"idcard mid banklink\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"ldap\",\"banklink\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=NO_VALID_AUTHMETHODS_AVAILABLE)");
    }

    @Test
    @Tag(value = "AUTH_INIT_ENABLED_AUTHMETHODS_ACR")
    void authInit_IncorrectAcrRequestedByOidc() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"wrongvalue\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcRespondsWith404() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
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

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_GovSsoOidcRespondsWith410() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
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

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_GovSsoOidcRespondsWith500() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response-ok_with_govsso_hydra_parameters.json")));

        govSsoWireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_GOVSSO_LOGIN_CHALLENGE))
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

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"govSsoClientId\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"},\"smartid_settings\":{\"relying_party_UUID\":\"testRelyingPartyId123\",\"relying_party_name\":\"testRelyingPartyName\",\"should_use_additional_verification_code_check\":false}}},\"scope\":\"idcard mid\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"low\"],\"ui_locales\":[]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[\"idcard\",\"mid\"]}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_NoRequestedScope() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA request", "http.request.method=GET, url.full=https://localhost:9877/admin/oauth2/auth/requests/login?login_challenge=abcdefg098AAdsCC");
        assertMessageWithMarkerIsLoggedOnce(AuthInitController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"challenge\":\"abcdefg098AAdsCC\",\"client\":{\"client_id\":\"openIdDemo\",\"metadata\":{\"display_user_consent\":false,\"oidc_client\":{\"institution\":{\"registry_code\":\"70006317\",\"sector\":\"public\"},\"name_translations\":{\"en\":\"test client en\",\"et\":\"test client et\",\"ru\":\"test client ru\"},\"short_name_translations\":{\"en\":\"short test client en\",\"et\":\"short test client et\",\"ru\":\"short test client ru\"}}},\"scope\":\"mid idcard\"},\"login_challenge_expired\":false,\"oidc_context\":{\"acr_values\":[\"high\"],\"ui_locales\":[\"zu\",\"fi\",\"Et\",\"RU\",\"en\"]},\"request_url\":\"https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et\",\"requested_scope\":[]}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=70006317, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=MISSING_SCOPE)");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_OidcResponseBodyContainsInvalidParameters() {
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWhenRequestedCountryIsInvalid() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWithCountriesListForPublicSector() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly_with_invalid_country.json")));
        String expectedCountriesRegex = ".*<select id=\"country-select\" name=\"country\">\\s*<option value=\"\">Select your country</option>\\s*<option value=\"CA\">Test \\(CA\\)</option>\\s*</select>.*";
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
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_displayEidasAuthenticationPageWithCountriesListForPrivateSector() {
        eidasConfigurationProperties.setAvailableCountries(AVAILABLE_COUNTRIES);
        RestAssured.responseSpecification = null;
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_eidasonly_with_invalid_country_private_sector.json")));
        String expectedCountriesRegex = ".*<select id=\"country-select\" name=\"country\">\\s*<option value=\"\">Select your country</option>\\s*<option value=\"IT\">Italy</option>\\s*</select>.*";
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
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "AUTH_INIT_GOVSSO_GET_OIDC_REQUEST")
    void authInit_govSsoLoginChallengeIsEmpty() {

        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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


    @ParameterizedTest
    @ValueSource(strings = {"now", "20"})
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_okBeforeAuthFlowTimeout(String secondsToTimeout) {
        OffsetDateTime formattedTimeout = OffsetDateTime.now();
        if (!secondsToTimeout.equals("now")) {
            formattedTimeout = OffsetDateTime.now().minus(authConfigurationProperties.getAuthFlowTimeout()).plusSeconds(Long.parseLong(secondsToTimeout));
        }
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_response_requested_at_param.json")
                        .withTransformerParameter("requestedAt", formattedTimeout.toInstant().getEpochSecond())));

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
                .cookie(TARA_SESSION_COOKIE_NAME, matchesPattern("[A-Za-z0-9,-]{36,36}"))
                .extract().cookie(TARA_SESSION_COOKIE_NAME);

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_AUTH_PROCESS, taraSession.getState());
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_afterAuthFlowTimeout() {
        OffsetDateTime formattedTimeout = OffsetDateTime.now().minus(authConfigurationProperties.getAuthFlowTimeout())
            .minusSeconds(1);
        wireMockServer.stubFor(
            get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json; charset=UTF-8")
                    .withBodyFile("mock_responses/oidc/mock_response_requested_at_param.json")
                    .withTransformers("response-template")
                    .withTransformerParameter("requestedAt", formattedTimeout.toInstant().getEpochSecond())));

        wireMockServer.stubFor(
            put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json; charset=UTF-8")
                    .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        String sessionId = given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(401)
            .body("message", equalTo(
                "Autentimiseks ettenähtud aeg lõppes. Peate autentimisprotsessi teenusepakkuja juurest uuesti alustama."))
            .body("error", equalTo("Unauthorized"))
            .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
            .body("reportable", equalTo(false))
            .body("redirect_to_service_provider", equalTo(true))
            .body("redirect_to_service_provider_url", equalTo("/some/test/url"))
            .extract().cookie(TARA_SESSION_COOKIE_NAME);

        assertNull(sessionRepository.findById(sessionId), "Session should be invalidated");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"/some/test/url\"}");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_afterAuthFlowTimeoutWithOidcError() {
        OffsetDateTime formattedTimeout = OffsetDateTime.now().minus(authConfigurationProperties.getAuthFlowTimeout()).minusSeconds(1);
        wireMockServer.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/oidc/mock_response_requested_at_param.json")
                .withTransformers("response-template")
                .withTransformerParameter("requestedAt", formattedTimeout.toInstant().getEpochSecond())));

        wireMockServer.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        given()
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(500)
            .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
            .body("error", equalTo("Internal Server Error"))
            .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
            .body("reportable", equalTo(true));

        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
    }

    @Test
    @Tag(value = "AUTH_INIT_GET_OIDC_REQUEST")
    void authInit_AfterAuthFlowTimeoutHtmlError() {
        OffsetDateTime formattedTimeout = OffsetDateTime.now().minus(authConfigurationProperties.getAuthFlowTimeout())
            .minusSeconds(1);
        wireMockServer.stubFor(
            get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json; charset=UTF-8")
                    .withBodyFile("mock_responses/oidc/mock_response_requested_at_param.json")
                    .withTransformers("response-template")
                    .withTransformerParameter("requestedAt", formattedTimeout.toInstant().getEpochSecond())));

        wireMockServer.stubFor(
            put(urlEqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json; charset=UTF-8")
                    .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        String responseBody = given()
            .header("Accept", "text/html")
            .param("login_challenge", TEST_LOGIN_CHALLENGE)
            .when()
            .get("/auth/init")
            .then()
            .assertThat()
            .statusCode(401)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + CHARSET_UTF_8)
            .extract()
            .body()
            .asString();
        assertTrue(responseBody.contains("<a href=\"/some/test/url\">Tagasi teenusepakkuja juurde</a>"),
            "Response body should contain the expected <a> tag with href and text content.");

        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/admin/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"User canceled the authentication process.\",\"error_description\":\"User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"/some/test/url\"}");
    }
}
