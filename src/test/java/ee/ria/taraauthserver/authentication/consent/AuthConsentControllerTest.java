package ee.ria.taraauthserver.authentication.consent;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDate;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;

@Slf4j
class AuthConsentControllerTest extends BaseTest {

    public static final String MOCK_CONSENT_CHALLENGE = "abcdefg098AAdsCC";

    @Autowired
    SessionRepository sessionRepository;

    @Test
    void authConsent_display() {
        Session session = createSessionWithAuthenticationState(TaraAuthenticationState.AUTHENTICATION_SUCCESS, true);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .queryParam("consent_challenge", "abc123")
                .get("/consent")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void authConsent_redirect() {
        Session session = createSessionWithAuthenticationState(TaraAuthenticationState.AUTHENTICATION_SUCCESS, false);

        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + MOCK_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .queryParam("consent_challenge", MOCK_CONSENT_CHALLENGE)
                .get("/consent")
                .then()
                .assertThat()
                .statusCode(302);
    }

    @SneakyThrows
    private Session createSessionWithAuthenticationState(TaraAuthenticationState authenticationState, boolean display) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession();
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.MetaData md = new TaraSession.MetaData();
        TaraSession.Client client = new TaraSession.Client();
        md.setDisplay_user_consent(display);
        client.setMetaData(md);
        lri.setClient(client);
        lri.setUrl(new URL("https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c80393c7-6666-4dd2-b890-0ada47161cfa&nonce=fa97f828-eda3-4975-bca2-4bfbb9b24d28&ui_locales=et"));
        authSession.setLoginRequestInfo(lri);

        TaraSession.AuthenticationResult ar = new TaraSession.AuthenticationResult();
        ar.setIdCode("abc123idcode");
        ar.setFirstName("firstname");
        ar.setLastName("lastname");
        ar.setDateOfBirth(LocalDate.of(1992, 12, 17));
        authSession.setAuthenticationResult(ar);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session;
    }

}