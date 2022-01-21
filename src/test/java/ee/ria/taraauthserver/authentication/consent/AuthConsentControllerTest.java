package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.BaseTest;
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

import java.net.URL;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Slf4j
class AuthConsentControllerTest extends BaseTest {

    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_consentChallenge_EmptyValue() {
        given()
                .param("consent_challenge", "")
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsent.consentChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_consentChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'consent_challenge' is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Required String parameter 'consent_challenge' is not present");
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_consentChallenge_InvalidValue() {
        given()
                .param("consent_challenge", "......")
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsent.consentChallenge: only characters and numbers allowed"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authConsent.consentChallenge: only characters and numbers allowed");
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_consentChallenge_InvalidLength() {
        given()
                .param("consent_challenge", "123456789012345678901234567890123456789012345678900")
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("authConsent.consentChallenge: size must be between 0 and 50"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: authConsent.consentChallenge: size must be between 0 and 50");
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_consentChallenge_DuplicatedParam() {
        given()
                .param("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .param("consent_challenge", "abcdefg098AAdsCCasassa")
                .when()
                .get("/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Multiple request parameters with the same name not allowed"))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_session_missing() {

        given()
                .when()
                .queryParam("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    void authConsent_wrong_authentication_state() {
        Session session = createSession(TaraAuthenticationState.INIT_MID, true, List.of("openid"));

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .queryParam("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [AUTHENTICATION_SUCCESS]");
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    @Tag(value = "USER_CONSENT_REQUIRED")
    @Tag(value = "UI_CONSENT_VIEW")
    void authConsent_display() {
        Session session = createSession(TaraAuthenticationState.AUTHENTICATION_SUCCESS, true, List.of("openid"));

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .queryParam("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("firstname"))
                .body(containsString("lastname"))
                .body(containsString("abc123idcode"))
                .body(containsString("17.12.1992"))
                .body(not(containsString("123456789")))
                .body(not(containsString("phone-number")))
                .header(HttpHeaders.CONTENT_TYPE, "text/html;charset=UTF-8");

        TaraSession taraSession = sessionRepository.findById(session.getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_CONSENT_PROCESS, taraSession.getState());
        assertEquals(MOCK_CONSENT_CHALLENGE, taraSession.getConsentChallenge());
    }

    @Test
    @Tag(value = "USER_CONSENT_ENDPOINT")
    @Tag(value = "USER_CONSENT_NOT_REQUIRED")
    void authConsent_redirect() {
        Session session = createSession(TaraAuthenticationState.AUTHENTICATION_SUCCESS, false, List.of("openid"));

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withHeader(HttpHeaders.CONNECTION, "close")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .queryParam("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "http://localhost:" + port + "/auth/some/test/url");

        assertInfoIsLogged("Tara session state change: AUTHENTICATION_SUCCESS -> CONSENT_NOT_REQUIRED");
        assertInfoIsLogged("Session is removed from cache: " + session.getId());
        assertWarningIsLogged("Session has been invalidated: " + session.getId());
        assertNull(sessionRepository.findById(session.getId()));
    }

    @SneakyThrows
    private Session createSession(TaraAuthenticationState authenticationState, boolean display, List<String> requestedScopes) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.MetaData md = new TaraSession.MetaData();
        TaraSession.Client client = new TaraSession.Client();
        md.setDisplayUserConsent(display);
        client.setMetaData(md);
        client.setScope("mid idcard");
        lri.setClient(client);
        lri.setRequestedScopes(requestedScopes);
        lri.setUrl(new URL("https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et"));
        authSession.setLoginRequestInfo(lri);
        TaraSession.AuthenticationResult ar = new TaraSession.AuthenticationResult();
        ar.setIdCode("abc123idcode");
        ar.setFirstName("firstname");
        ar.setLastName("lastname");
        ar.setDateOfBirth(LocalDate.of(1992, 12, 17));
        ar.setAcr(LevelOfAssurance.HIGH);
        ar.setAmr(AuthenticationType.MOBILE_ID);
        ar.setPhoneNumber("123456789");
        authSession.setAuthenticationResult(ar);
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.ID_CARD);
        authSession.setAllowedAuthMethods(allowedMethods);
        TaraSession.LegalPerson legalPerson = new TaraSession.LegalPerson("legalName", "identifier123");
        authSession.setSelectedLegalPerson(legalPerson);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session;
    }

}