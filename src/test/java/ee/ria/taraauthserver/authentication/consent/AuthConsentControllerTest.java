package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthConsentControllerTest extends BaseTest {

    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    SessionRepository sessionRepository;

    @Test
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
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    void authConsent_consentChallenge_ParamMissing() {
        given()
                .when()
                .get("/auth/consent")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Required String parameter 'consent_challenge' is not present"))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: Required String parameter 'consent_challenge' is not present");
    }

    @Test
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
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: authConsent.consentChallenge: only characters and numbers allowed");
    }

    @Test
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
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: authConsent.consentChallenge: size must be between 0 and 50");
    }

    @Test
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

        assertErrorIsLogged("User exception: Session was not found");
    }

    @Test
    void authConsent_wrong_authentication_state() {
        Session session = createSession(TaraAuthenticationState.INIT_MID, true);

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

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected: 'AUTHENTICATION_SUCCESS'");
    }

    @Test
    void authConsent_display() {
        Session session = createSession(TaraAuthenticationState.AUTHENTICATION_SUCCESS, true);

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
                .header(HttpHeaders.CONTENT_TYPE, "text/html;charset=UTF-8");

        TaraSession taraSession = sessionRepository.findById(session.getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.INIT_CONSENT_PROCESS, taraSession.getState());
        assertEquals(MOCK_CONSENT_CHALLENGE, taraSession.getConsentChallenge());
    }

    @Test
    void authConsent_redirect() {
        Session session = createSession(TaraAuthenticationState.AUTHENTICATION_SUCCESS, false);

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
                .statusCode(302);

        TaraSession taraSession = sessionRepository.findById(session.getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.CONSENT_NOT_REQUIRED, taraSession.getState());
    }

    @SneakyThrows
    private Session createSession(TaraAuthenticationState authenticationState, boolean display) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession();
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.MetaData md = new TaraSession.MetaData();
        TaraSession.Client client = new TaraSession.Client();
        md.setDisplay_user_consent(display);
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