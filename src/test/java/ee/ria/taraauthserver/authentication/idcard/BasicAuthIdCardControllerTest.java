package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.TestPropertySource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.authentication.idcard.IdCardController.HEADER_SSL_CLIENT_CERT;
import static ee.ria.taraauthserver.authentication.idcard.IdCardControllerTest.X509_CERT;
import static ee.ria.taraauthserver.authentication.idcard.IdCardControllerTest.setUpMockOcspResponse;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateOcspResponderCertificate;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Slf4j
@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.id-card.basic-auth.enabled=true",
                "tara.auth-methods.id-card.basic-auth.username=user",
                "tara.auth-methods.id-card.basic-auth.password=password"})
class BasicAuthIdCardControllerTest extends BaseTest {
    private final AuthConfigurationProperties.Ocsp ocspConfiguration = new AuthConfigurationProperties.Ocsp();
    private KeyPair responderKeys;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @BeforeEach
    public void setUpTest() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, CertIOException, OperatorCreationException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);
        RestAssured.responseSpecification = null;

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());

        setUpMockOcspResponse(IdCardControllerTest.MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
    }

    @Test
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void idAuth_access_denied() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .auth()
                .preemptive()
                .basic("user", "invalid_password")
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(401)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8")
                .body("error", equalTo("Unauthorized"));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void idAuth_access_granted() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .auth()
                .preemptive()
                .basic("user", "password")
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8")
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("37101010021", result.getIdCode());
        assertEquals("IGOR", result.getFirstName());
        assertEquals("ŽAIKOVSKI", result.getLastName());
        assertEquals("1971-01-01", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertNull(result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=EE, idCode=37101010021, ocspUrl=https://localhost:9877/esteid2015, authenticationType=ID_CARD, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    private String createSessionWithAuthenticationState(TaraAuthenticationState authenticationState) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.getClient().getMetaData().getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        authSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }
}
