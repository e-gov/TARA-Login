package ee.ria.taraauthserver.authentication.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
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
import org.springframework.test.annotation.DirtiesContext;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.authentication.idcard.IdCardController.HEADER_SSL_CLIENT_CERT;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateOcspResponderCertificate;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateUserCertificate;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class IdCardControllerTest extends BaseTest {
    private final AuthConfigurationProperties.Ocsp ocspConfiguration = new AuthConfigurationProperties.Ocsp();
    private KeyPair responderKeys;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;

    @BeforeEach
    public void setUpTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);
        RestAssured.responseSpecification = null;
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "ESTEID_AUTH_ENDPOINT")
    void idAuth_certificate_missing() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("ID-kaardi sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertErrorIsLogged("User exception: XCLIENTCERTIFICATE can not be null");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "ESTEID_AUTH_ENDPOINT")
    void idAuth_certificate_missing_html_response() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        Response response = given()
                .when()
                .header("Accept", "text/html")
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400).contentType(ContentType.HTML).extract()
                .response();

        assertTrue(response.body().htmlPath().getInt("**.find { strong -> strong.text() == 'Kasutaja tuvastamine ebaõnnestus.'}.size()") > 0);
        assertTrue(response.body().htmlPath().getInt("**.find { p -> p.text() == 'ID-kaardi sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti.'}.size()") > 0);
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Intsidendi number:"));
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.a.@href").contains("mailto:"));
        assertTrue(response.body().htmlPath().getString("**.find { it.@role == 'alert'}.p.text()").contains("Palun saatke e-kiri aadressile"));
        assertErrorIsLogged("User exception: XCLIENTCERTIFICATE can not be null");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "ESTEID_AUTH_ENDPOINT")
    void idAuth_certificate_incorrect() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, "testing")
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Internal Server Error"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertErrorIsLogged("Server encountered an unexpected error: Failed to decode certificate");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "ESTEID_AUTH_ENDPOINT")
    void idAuth_certificate_empty_string() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .header(HEADER_SSL_CLIENT_CERT, "")
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("ID-kaardi sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertErrorIsLogged("User exception: XCLIENTCERTIFICATE can not be an empty string");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    void idAuth_session_missing() {
        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    void idAuth_session_incorrect_authentication_state() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_MID);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void idAuth_ok() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
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
        assertEquals("47101010033", result.getIdCode());
        assertEquals("MARI-LIIS", result.getFirstName());
        assertEquals("MÄNNIK", result.getLastName());
        assertEquals("1971-01-01", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertNull(result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void idAuth_ok_with_email() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        TaraSession.Client client = new TaraSession.Client();
        client.setScope("openid email");
        loginRequestInfo.setClient(client);
        loginRequestInfo.setRequestedScopes(List.of("email", "openid"));
        authSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        String sessionId = session.getId();

        given()
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
        assertEquals("47101010033", result.getIdCode());
        assertEquals("MARI-LIIS", result.getFirstName());
        assertEquals("MÄNNIK", result.getLastName());
        assertEquals("1971-01-01", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertEquals("mari-liis.mannik@eesti.ee", result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsNotLogged();
    }

    @Test
    @DirtiesContext
    @Tag(value = "OCSP_DISABLED")
    void idAuth_ok_ocsp_disabled() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        configurationProperties.setOcspEnabled(false); // TODO AUT-857
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
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

        assertInfoIsLogged("Skipping OCSP validation because OCSP is disabled.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void idAuth_response_certificate_status_revoked() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(new RevokedStatus(
                        new Date(), CRLReason.unspecified
                ))
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("ERROR"))
                .body("message", equalTo("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertWarningIsLogged("OCSP validation failed: Invalid certificate status <REVOKED> received");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_REVOKED)");
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void idAuth_response_certificate_status_unknown() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(new UnknownStatus())
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("ERROR"))
                .body("message", equalTo("ID-kaardi sertifikaadi staatus on teadmata."));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertWarningIsLogged("OCSP validation failed: Invalid certificate status <UNKNOWN> received");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_UNKNOWN)");
    }

    @Test
    @Tag(value = "OCSP_FAILOVER_CONF")
    void idAuth_response_200_when_response_is_404_and_fallback_service_is_used() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2015").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/ocsp");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("COMPLETED"));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "OCSP_CA_WHITELIST")
    void idAuth_response_500_when_issuer_certificate_not_trusted() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=\"MOCK OCSP RESPONDER\", C=EE", certKeyPair, responderKeys, "CN=WRONG CN").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=\"MOCK OCSP RESPONDER\"")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .headers(EXPECTED_RESPONSE_HEADERS)
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: Issuer certificate with CN 'WRONG CN' is not a trusted certificate!");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "OCSP_RESPONSE_VALID_SIG")
    void idAuth_response_500_when_responder_certificate_issuer_different_from_user() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=\"MOCK OCSP RESPONDER\", C=EE", certKeyPair, responderKeys, "CN=TEST of ESTEID-SK 2011").getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(CertificateStatus.GOOD)
                .responseId("CN=\"MOCK OCSP RESPONDER\"")
                .ocspConf(ocspConfiguration)
                .responderCertificate(
                        ocspResponderCert
                ).build(), "/esteid2015");
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .headers(EXPECTED_RESPONSE_HEADERS)
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: In case of AIA OCSP, the OCSP responder certificate must be issued by the authority that issued the user certificate. Expected issuer: 'CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE', but the OCSP responder signing certificate was issued by 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE'");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "OCSP_VALID_RESPONSE")
    void idAuth_response_500_when_response_body_is_missing() {
        wireMockServer.stubFor(WireMock.post("/esteid2015")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withTransformer("ocsp", "ignore", true)
                        .withHeader("Content-Type", "application/ocsp-response")));
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .headers(EXPECTED_RESPONSE_HEADERS)
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: malformed response: no response data found");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2015, http.request.body.content={\"http.request.body.content\":");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "OCSP_VALID_RESPONSE")
    void idAuth_response_ocspService_notAvailable() {
        wireMockServer.stubFor(get(urlEqualTo("/esteid2015"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)));
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(502)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("ERROR"))
                .body("message", equalTo("ID-kaardi sertifikaadi kehtivuse info küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertWarningIsLogged("OCSP validation failed: OCSP service is currently not available");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_OCSP_NOT_AVAILABLE)");
    }

    @Test
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void idAuth_response_userCert_notYetValid() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        X509Certificate userCert = generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE",
                responderKeys,
                "CN=TEST of ESTEID-SK 2015",
                Date.from(Instant.now().plus(Duration.ofHours(1))), Date.from(Instant.now().plus(Duration.ofHours(2)))).getCertificate();
        String cert = formatCrtFileContents(userCert);
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, cert)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("ERROR"))
                .body("message", equalTo("ID-kaardi sertifikaadid ei kehti."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        assertWarningIsLogged("OCSP validation failed: User certificate is not yet valid");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_CERT_NOT_YET_VALID)");
    }

    @Test
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void idAuth_response_userCert_expired() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        X509Certificate userCert = generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE",
                responderKeys,
                "CN=TEST of ESTEID-SK 2015",
                Date.from(Instant.now().minus(Duration.ofHours(2))), Date.from(Instant.now().minus(Duration.ofHours(1)))).getCertificate();
        String cert = formatCrtFileContents(userCert);
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, cert)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("ERROR"))
                .body("message", equalTo("ID-kaardi sertifikaadid ei kehti."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36,36}"));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertWarningIsLogged("OCSP validation failed: User certificate is expired");

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(clientId=null, sector=null, registryCode=null, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_CERT_EXPIRED)");
    }

    private String createSessionWithAuthenticationState(TaraAuthenticationState authenticationState) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(authenticationState);
        authSession.setLoginRequestInfo(new TaraSession.LoginRequestInfo());
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }

    @Builder
    @Data
    static class MockOcspResponseParams {
        int responseStatus;
        CertificateStatus certificateStatus;
        int delay;
        WireMockServer ocspServer;
        String responseId;
        X509Certificate responderCertificate;
        String signatureAlgorithm;
        AuthConfigurationProperties.Ocsp ocspConf;
    }

    static void setUpMockOcspResponse(MockOcspResponseParams responseParams, String stubUrl) {
        ocspResponseTransformer.setResponseStatus(responseParams.getResponseStatus());
        ocspResponseTransformer.setCertificateStatus(responseParams.getCertificateStatus());
        ocspResponseTransformer.setResponderCertificate(responseParams.getResponderCertificate());

        responseParams.getOcspServer().stubFor(WireMock.post(stubUrl)
                .willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withTransformers("ocsp")
                                .withTransformerParameter("responderId", responseParams.getResponseId())
                                .withTransformerParameter("signatureAlgorithm", responseParams.getSignatureAlgorithm() == null ? "SHA256withRSA" : responseParams.getSignatureAlgorithm())
                                .withTransformerParameter("ocspConf", responseParams.getOcspConf())
                                .withFixedDelay(responseParams.getDelay())
                                .withHeader("Content-Type", "application/ocsp-response")
                )
        );
    }

    public static String formatCrtFileContents(final X509Certificate certificate) throws CertificateEncodingException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        return BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
    }

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public final static String LINE_SEPARATOR = System.getProperty("line.separator");

    public static final String X509_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGRDCCBCygAwIBAgIQFRkmAJhm0EFZ3Lplb5xtuzANBgkqhkiG9w0BAQsFADBr\n" +
            "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\n" +
            "czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNU\n" +
            "RUlELVNLIDIwMTUwHhcNMTcxMDEwMTIxNzQxWhcNMjIxMDA5MjA1OTU5WjCBmzEL\n" +
            "MAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEXMBUGA1UECwwOYXV0aGVudGlj\n" +
            "YXRpb24xJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDQ3MTAxMDEwMDMzMRAw\n" +
            "DgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzQ3\n" +
            "MTAxMDEwMDMzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVAcrw263vwciSE9i5rP2\n" +
            "3NJq2YqKo8+fk9kSDIflVJICplDiN9lz5uh69ICfygyxmwgLB3m8opoAfSTOdkGI\n" +
            "SyLR7E/76AppfdWQe7NO0YV2DZrEA4FU3xNGotfJNOrAo4ICXzCCAlswCQYDVR0T\n" +
            "BAIwADAOBgNVHQ8BAf8EBAMCA4gwgYkGA1UdIASBgTB/MHMGCSsGAQQBzh8DATBm\n" +
            "MC8GCCsGAQUFBwIBFiNodHRwczovL3d3dy5zay5lZS9yZXBvc2l0b29yaXVtL0NQ\n" +
            "UzAzBggrBgEFBQcCAjAnDCVBaW51bHQgdGVzdGltaXNla3MuIE9ubHkgZm9yIHRl\n" +
            "c3RpbmcuMAgGBgQAj3oBAjAkBgNVHREEHTAbgRltYXJpLWxpaXMubWFubmlrQGVl\n" +
            "c3RpLmVlMB0GA1UdDgQWBBTk9OenGSkT7fZr6ssshuWFSD17VjBhBggrBgEFBQcB\n" +
            "AwRVMFMwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5\n" +
            "L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAgBgNVHSUB\n" +
            "Af8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUScDyRDll1ZtG\n" +
            "Ow04YIOx1i0ohqYwgYMGCCsGAQUFBwEBBHcwdTAsBggrBgEFBQcwAYYgaHR0cDov\n" +
            "L2FpYS5kZW1vLnNrLmVlL2VzdGVpZDIwMTUwRQYIKwYBBQUHMAKGOWh0dHBzOi8v\n" +
            "c2suZWUvdXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRVNURUlELVNLXzIwMTUuZGVyLmNy\n" +
            "dDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlk\n" +
            "L3Rlc3RfZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBALhg4bhXry4H\n" +
            "376mvyZhMYulobeFAdts9JQYWk5de2+lZZiTcX2yHbAF80DlW1LZe9NczCbF991o\n" +
            "5ZBYP80Tzc+42urBeUesydVEkB+9Qzv/d3+eCU//jN4seoeIyxfSP32JJefgT3V+\n" +
            "u2dkvTPx5HLz3gfptQ7L6usNY5hCxxcxtxW/zKj28qKLH3cQlryZbAxLy+C3aIDD\n" +
            "tlf/OPLWFDZt3bDogehCGYdgwsAz7pur1gKn7UXOnFX+Na5zGQPPgyH+nwgby3Zs\n" +
            "GC8Hy4K4I98q+wcfykJnbT/jtTZBROOiS8br27oLEYgVY9iaTyL92arvLSQHc2jW\n" +
            "MwDQFptJtCnMvJbbuo31Mtg0nw1kqCmqPQLyMLRAFpxRxXOrOCArmPET6u4i9VYm\n" +
            "e5M5uuwS4BmnnZTmDbkLz/1kMqbYc7QRynsh7Af7oVI15qP3iELtMWLWVHafpE+q\n" +
            "YWOE2nwbnlKjt6HGsGno6gcrnOYhlO6/VXfNLPfvZn0OHGiAT1v6YyFQyeYxqfGF\n" +
            "0OxAOt06wDLEBd7p9cuPHuu8OxuLO0478YXyWdwWeHbJgthAlbaTKih+jW4Cahsc\n" +
            "0kpQarrExgPQ00aInw1tVifbEYcRhB25YOiIDlSPORenQ+SdkT6OyU3wJ8rArBs4\n" +
            "OfEkPnSsNkNa+PeTPPpPZ1LgmhoczuQ3\n" +
            "-----END CERTIFICATE-----";
}