package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.SneakyThrows;
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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.SecurityConfiguration.TARA_SESSION_CSRF_TOKEN;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_CONSENT_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_MID;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthConsentConfirmControllerTest extends BaseTest {
    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";

    @Test
    @Tag("CSRF_PROTCTION")
    void authConsent_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(403)
                .body("message", equalTo("Forbidden"))
                .body("path", equalTo("/auth/consent/confirm"));
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_consentGiven_ParamMissing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'consent_given' is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Required String parameter 'consent_given' is not present");
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_consentGiven_InvalidValue() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .param("consent_given", "invalidvalue")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsentConfirm.consentGiven: supported values are: 'true', 'false'"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: authConsentConfirm.consentGiven: supported values are: 'true', 'false'");
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_session_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "USER_CONSENT_CONFIRM_ENDPOINT")
    void authConsent_wrong_authentication_state() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(INIT_MID).build())
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_CONSENT_PROCESS]");
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

        Session session = createSession();
        given()
                .filter(new MockSessionFilter(session))
                .queryParam("consent_given", "true")
                .when()
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302);

        assertNull(sessionRepository.findById(session.getId()));
        assertWarningIsLogged("Session '" + session.getId() + "' has been invalidated");
    }

    @Test
    @Tag(value = "USER_CONSENT_POST_ACCEPT")
    void authConsent_acceptNoRedirect() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        Session session = createSession();
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

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        TaraSession taraSession = sessionRepository.findById(session.getId()).getAttribute(TARA_SESSION);
        assertEquals(INIT_CONSENT_PROCESS, taraSession.getState());
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

        Session session = createSession();
        given()
                .filter(new MockSessionFilter(session))
                .when()
                .queryParam("consent_given", "false")
                .post("/auth/consent/confirm")
                .then()
                .assertThat()
                .statusCode(302);

        assertNull(sessionRepository.findById(session.getId()));
        assertWarningIsLogged("Session '" + session.getId() + "' has been invalidated");
    }

    @Test
    @Tag(value = "USER_CONSENT_POST_REJECT")
    void authConsent_rejectNoRedirect() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/reject?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/incorrectMockLoginAcceptResponse.json")));

        Session session = createSession();
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

        assertErrorIsLogged("Server encountered an unexpected error: Invalid OIDC server response. Redirect URL missing from response.");
        TaraSession taraSession = sessionRepository.findById(session.getId()).getAttribute(TARA_SESSION);
        assertEquals(INIT_CONSENT_PROCESS, taraSession.getState());
    }

    @SneakyThrows
    private Session createSession() {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(INIT_CONSENT_PROCESS);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.MetaData md = new TaraSession.MetaData();
        TaraSession.Client client = new TaraSession.Client();
        md.setDisplayUserConsent(true);
        client.setMetaData(md);
        client.setScope("mid idcard");
        lri.setClient(client);
        lri.setUrl(new URL("https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et"));
        authSession.setLoginRequestInfo(lri);
        TaraSession.AuthenticationResult ar = new TaraSession.AuthenticationResult();
        ar.setIdCode("abc123idcode");
        ar.setFirstName("firstname");
        ar.setLastName("lastname");
        ar.setDateOfBirth(LocalDate.of(1992, 12, 17));
        ar.setAcr(LevelOfAssurance.HIGH);
        ar.setAmr(AuthenticationType.MOBILE_ID);
        authSession.setAuthenticationResult(ar);
        authSession.setConsentChallenge(MOCK_CONSENT_CHALLENGE);
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.ID_CARD);
        authSession.setAllowedAuthMethods(allowedMethods);
        session.setAttribute(TARA_SESSION, authSession);
        session.setAttribute(TARA_SESSION_CSRF_TOKEN, new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString()));
        sessionRepository.save(session);
        return session;
    }
}
