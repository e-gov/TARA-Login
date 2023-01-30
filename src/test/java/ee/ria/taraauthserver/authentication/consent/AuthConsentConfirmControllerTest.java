package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.SneakyThrows;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.session.Session;

import java.net.URL;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_HEADER_NAME;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_PARAMETER_NAME;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_TOKEN_ATTR_NAME;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_MID;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthConsentConfirmControllerTest extends BaseTest {
    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";
    public static final String URL = "https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et";

    @Test
    @Tag("CSRF_PROTECTION")
    void authConsent_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_consentGiven_ParamMissing() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required request parameter 'consent_given' for method parameter type String is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Required request parameter 'consent_given' for method parameter type String is not present");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_consentGiven_InvalidValue() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .param("consent_given", "invalidvalue")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsentConfirm.consentGiven: supported values are: 'true', 'false'"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authConsentConfirm.consentGiven: supported values are: 'true', 'false'");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag("USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag("CSRF_PROTECTION")
    void authConsent_session_missing() {
        given()
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_wrong_authentication_state() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(INIT_MID).build())
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_CONSENT_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("openid"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: INIT_CONSENT_PROCESS -> CONSENT_GIVEN");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful_with_url_missing_lang_parameter() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("openid"), "https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=");

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url")).extract().response();

        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful_with_url_state_parameter_containing_equals_sign() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("openid"), "https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa=&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et");

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url")).extract().response();

        wireMockServer.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC"))
                .withRequestBody(containing("c80393c7-6666-4dd2-b890-0ada47161cfa=")));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa=\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful_phone_requested() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("phone", "email"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302);

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: INIT_CONSENT_PROCESS -> CONSENT_GIVEN");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"phone_number\":\"112233\",\"phone_number_verified\":true,\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful_email_requested() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(ID_CARD, List.of("phone", "email"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302);

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: INIT_CONSENT_PROCESS -> CONSENT_GIVEN");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"email\":\"test@test.ee\",\"email_verified\":false,\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptSuccessful_withGovSsoLoginChallenge() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("openid"), "https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&govsso_login_challenge=govSsoLoginChallenge&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et", true);

        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: INIT_CONSENT_PROCESS -> CONSENT_GIVEN");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"govsso_login_challenge\":\"aabbcc\",\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptNoRedirect() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("phone", "email"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .when()
                .queryParam("consent_given", "true")
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"));

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/accept?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"grant_scope\":[\"openid\"],\"remember\":false,\"session\":{\"id_token\":{\"phone_number\":\"112233\",\"phone_number_verified\":true,\"profile_attributes\":{\"date_of_birth\":\"1992-12-17\",\"family_name\":\"lastname\",\"given_name\":\"firstname\"},\"state\":\"c80393c7-6666-4dd2-b890-0ada47161cfa\"}}}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=EE, idCode=abc123idcode, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "USER_CONSENT_POST_REJECT")
    void authConsent_rejectSuccessful() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/reject?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("phone", "email"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .when()
                .queryParam("consent_given", "false")
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.endsWith("some/test/url"));

        assertNull(sessionRepository.findById(session.getId()));
        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertInfoIsLogged("State: INIT_CONSENT_PROCESS -> CONSENT_NOT_GIVEN");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/reject?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"Consent not given. User canceled the authentication process.\",\"error_description\":\"Consent not given. User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={\"redirect_to\":\"some/test/url\"}");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "USER_CONSENT_POST_REJECT")
    void authConsent_rejectNoRedirect() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/reject?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));
        Session session = createSession(MOBILE_ID, List.of("phone", "email"), URL);

        given()
                .filter(new MockSessionFilter(session))
                .when()
                .queryParam("consent_given", "false")
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"));

        assertInfoIsLogged("State: NOT_SET -> INIT_CONSENT_PROCESS");
        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA request", "http.request.method=PUT, url.full=https://localhost:9877/oauth2/auth/requests/consent/reject?consent_challenge=abcdefg098AAdsCC, http.request.body.content={\"error\":\"user_cancel\",\"error_debug\":\"Consent not given. User canceled the authentication process.\",\"error_description\":\"Consent not given. User canceled the authentication process.\"}");
        assertMessageWithMarkerIsLoggedOnce(AuthConsentConfirmController.class, INFO, "TARA_HYDRA response: 200", "http.response.status_code=200, http.response.body.content={}");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=EE, idCode=abc123idcode, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @SneakyThrows
    private Session createSession(AuthenticationType authenticationType, List<String> requestedScopes, String url) {
        return createSession(authenticationType, requestedScopes, url, false);
    }

    @SneakyThrows
    private Session createSession(AuthenticationType authenticationType, List<String> requestedScopes, String url, boolean hasGovSsoLoginRequestInfo) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(INIT_CONSENT_PROCESS);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.MetaData md = new TaraSession.MetaData();
        TaraSession.Client client = new TaraSession.Client();
        md.setDisplayUserConsent(true);
        md.getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        client.setMetaData(md);
        client.setScope("mid idcard");
        lri.setClient(client);
        lri.setRequestedScopes(requestedScopes);
        lri.setUrl(new URL(url));
        lri.setChallenge("aabbcc");
        authSession.setLoginRequestInfo(lri);
        if (hasGovSsoLoginRequestInfo)
            authSession.setGovSsoLoginRequestInfo(lri);
        TaraSession.AuthenticationResult ar = new TaraSession.AuthenticationResult();
        ar.setIdCode("abc123idcode");
        ar.setFirstName("firstname");
        ar.setLastName("lastname");
        ar.setDateOfBirth(LocalDate.of(1992, 12, 17));
        ar.setAcr(LevelOfAssurance.HIGH);
        ar.setAmr(authenticationType);
        ar.setPhoneNumber("112233");
        ar.setEmail("test@test.ee");
        authSession.setAuthenticationResult(ar);
        authSession.setConsentChallenge(MOCK_CONSENT_CHALLENGE);
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(authenticationType);
        authSession.setAllowedAuthMethods(allowedMethods);
        session.setAttribute(TARA_SESSION, authSession);
        session.setAttribute(CSRF_TOKEN_ATTR_NAME, new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, UUID.randomUUID().toString()));
        sessionRepository.save(session);
        return session;
    }
}
