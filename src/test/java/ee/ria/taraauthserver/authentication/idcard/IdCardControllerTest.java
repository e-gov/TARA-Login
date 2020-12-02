package ee.ria.taraauthserver.authentication.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.authentication.idcard.IdCardController.HEADER_SSL_CLIENT_CERT;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateOcspResponderCertificate;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateUserCertificate;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class IdCardControllerTest extends BaseTest {

    @Autowired
    private ResourceLoader resourceLoader;

    private static final String MOCK_USER_CERT_2018_PATH = "file:src/test/resources/id-card/38001085718(TEST_of_ESTEID2018).pem";

    private static final OCSPValidatorTest.OcspResponseTransformer ocspResponseTransformer = new OCSPValidatorTest.OcspResponseTransformer();

    @Autowired
    private AuthConfigurationProperties.Ocsp ocspConfiguration;
    private KeyPair responderKeys;
    private X509Certificate responderCert;

    @Autowired
    private SessionRepository sessionRepository;

    @BeforeAll
    public static void setUpAll() {
        configureWiremockServer(ocspResponseTransformer);
    }

    @BeforeEach
    public void setUpTest() throws OperatorCreationException, CertificateException, CertIOException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);

        keyPairGenerator.initialize(2048);

        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);


        responderCert = generateOcspResponderCertificate(
                "C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=ESTEID2018 AIA OCSP RESPONDER 201903,E=pki@sk.ee",
                responderKeys, responderKeys,
                "CN=MOCK CA").getCertificate();

    }

    @Test
    void idAuth_certificate_missing() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        given()
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: XCLIENTCERTIFICATE can not be null");
    }

    @Test
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
                .body("error", equalTo("Internal Server Error"));

        assertErrorIsLogged("Server encountered an unexpected error: Failed to decode certificate");
    }

    @Test
    void idAuth_session_missing() {
        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));
    }

    @Test
    void idAuth_session_empty_string() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .header(HEADER_SSL_CLIENT_CERT, "")
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: XCLIENTCERTIFICATE can not be an empty string");
    }

    @Test
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
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected: 'INIT_AUTH_PROCESS'");
    }

    @Test
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
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("47101010033", result.getIdCode());
        assertEquals("MARI-LIIS", result.getFirstName());
        assertEquals("MÄNNIK", result.getLastName());
        assertEquals("1971-01-01", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());

    }

    @Test
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
                .body("status", equalTo("ERROR"))
                .body("errorMessage", equalTo("Teie sertifikaadid ei kehti."));

        assertWarningIsLogged("OCSP validation failed: Invalid certificate status <REVOKED> received");
    }

    @Test
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
                .body("status", equalTo("ERROR"))
                .body("errorMessage", equalTo("Teie sertifikaadid ei kehti."));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);

        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT, taraSession.getState());
        assertWarningIsLogged("OCSP validation failed: Invalid certificate status <UNKNOWN> received");

    }

    @Test
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
                .body("status", equalTo("COMPLETED"));
    }

    @Test
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
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: Issuer certificate with CN 'WRONG CN' is not a trusted certificate!");
    }

    @Test
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
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: In case of AIA OCSP, the OCSP responder certificate must be issued by the authority that issued the user certificate. Expected issuer: 'CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE', but the OCSP responder signing certificate was issued by 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE'");
    }

    @Test
    void idAuth_response_500_when_response_body_is_missing() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {

        wireMockServer.stubFor(WireMock.post("/esteid2015")
                .willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
                                .withTransformerParameter("ignore", true)
                                .withHeader("Content-Type", "application/ocsp-response")
                )
        );

        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .header(HEADER_SSL_CLIENT_CERT, X509_CERT)
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: OCSP validation failed: malformed response: no response data found");
    }

    @Test
    void idAuth_response_ocspService_notAvailable() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {


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
                .body("status", equalTo("ERROR"))
                .body("errorMessage", equalTo("Sertifikaadi kehtivuse info küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));

        assertWarningIsLogged("OCSP validation failed: OCSP service is currently not available, please try again later");
    }

    @Test
    void idAuth_response_userCert_notYetValid() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        X509Certificate userCert =
                generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE", responderKeys, "CN=TEST of ESTEID-SK 2015",
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
                .body("status", equalTo("ERROR"))
                .body("errorMessage", equalTo("Teie sertifikaadid ei kehti."));

        assertWarningIsLogged("OCSP validation failed: User certificate is not yet valid");
    }

    @Test
    void idAuth_response_userCert_expired() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        X509Certificate userCert =
                generateUserCertificate("SERIALNUMBER=PNOEE-38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE", responderKeys, "CN=TEST of ESTEID-SK 2015",
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
                .body("status", equalTo("ERROR"))
                .body("errorMessage", equalTo("Teie sertifikaadid ei kehti."));

        assertWarningIsLogged("OCSP validation failed: User certificate is expired");
    }

    private String createSessionWithAuthenticationState(TaraAuthenticationState authenticationState) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession();
        authSession.setState(authenticationState);
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

    private static void setUpMockOcspResponse(MockOcspResponseParams responseParams, String stubUrl) {
        ocspResponseTransformer.setResponseStatus(responseParams.getResponseStatus());
        ocspResponseTransformer.setCertificateStatus(responseParams.getCertificateStatus());
        ocspResponseTransformer.setResponderCertificate(responseParams.getResponderCertificate());

        responseParams.getOcspServer().stubFor(WireMock.post(stubUrl)
                .willReturn(
                        WireMock.aResponse()
                                .withStatus(200)
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
        final String prettified_cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
        return prettified_cert;
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