package ee.ria.taraauthserver.authentication.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.idcard.IdCardLoginController.WebEidData;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorHandler;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockSessionFilter.CsrfMode;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.annotation.DirtiesContext;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest.generateOcspResponderCertificate;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
// This class is built for testing IdCardLoginController and does not thoroughly test the internals of
// web-eid-authtoken-validation-java library. Some of the library's most common validation errors are covered, but
// mostly we rely on the library being already covered by its own tests.
class IdCardLoginControllerTest extends BaseTest {
    private static final String TEST_NONCE = "dGVzdC1ub25jZQo=";
    private static final String EXPIRED_CERT_PATH = "id-card/48812040138(TEST_of_ESTEID-SK_2011).pem";
    private static final String NOT_YET_VALID_CERT_PATH = "id-card/not-yet-valid-cert.pem";
    // TODO: Expires in 2029-05-02
    private static final String VALID_CERT_PATH = "id-card/38001085718(TEST_of_ESTEID2018).cer.pem";
    private static final String PRIVATE_KEY_PATH = "id-card/38001085718(TEST_of_ESTEID2018).key.pem";
    private static final String PRIVATE_KEY_PASSWORD = "1234";
    private final AuthConfigurationProperties.Ocsp ocspConfiguration = new AuthConfigurationProperties.Ocsp();
    private static PrivateKey usersPrivateKey;
    private static String base64EncodedUserCertificate;
    private KeyPair responderKeys;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;

    @BeforeAll
    public static void setupTestClass() throws CertificateEncodingException {
        Certificate certificate = loadCertificateFromResource(VALID_CERT_PATH);
        usersPrivateKey = readPrivateKey(PRIVATE_KEY_PATH, PRIVATE_KEY_PASSWORD);
        base64EncodedUserCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    @BeforeEach
    public void setUpTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);
        responderKeys = keyPairGenerator.generateKeyPair();
        ocspResponseTransformer.setSignerKey(responderKeys.getPrivate());
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);
    }

    @Test
    @Tag(value = "CSRF_PROTECTION")
    void handleRequest_NoCsrf_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withoutCsrf()
                .sessionRepository(sessionRepository)
                .build();
        given()
                .filter(mockSessionFilter)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(403)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "CSRF_PROTECTION")
    void handleRequest_MissingSession_Fails() {
        given()
                .body(createRequestBody())
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(403)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Forbidden"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_IncorrectAuthenticationState_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .authenticationState(TaraAuthenticationState.INIT_MID)
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_NonceNotFoundInSession_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Challenge nonce was not found in the nonce store");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_NonceExpired_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .nonce(new ChallengeNonce(TEST_NONCE, ZonedDateTime.now().minusSeconds(1)))
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Challenge nonce has expired");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_InvalidAuthTokenFormat_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        body.getAuthToken().setFormat("INVALID FORMAT");
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Only token format version 'web-eid:1' is currently supported");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateMissing_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        body.getAuthToken().setUnverifiedCertificate(null);
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=null, tara.webeid.auth_token.signature=");
        assertErrorIsLogged(ErrorHandler.class, "User exception: 'unverifiedCertificate' field is missing, null or empty");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateEmpty_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        body.getAuthToken().setUnverifiedCertificate("");
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertErrorIsLogged(ErrorHandler.class, "User exception: 'unverifiedCertificate' field is missing, null or empty");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateInvalidContents_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        body.getAuthToken().setUnverifiedCertificate("SW52YWxpZCBjZXJ0aWZpY2F0ZQo="); // Base64-encoded string: "Invalid certificate"
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("Ebakorrektne päring."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=SW52YWxpZCBjZXJ0aWZpY2F0ZQo=, tara.webeid.auth_token.signature=");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Certificate decoding from Base64 or parsing failed");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateExpired_Fails() throws CertificateEncodingException {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        X509Certificate certificate = loadCertificateFromResource(EXPIRED_CERT_PATH);
        String base64EncodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        WebEidData body = createRequestBody();
        body.getAuthToken().setUnverifiedCertificate(base64EncodedCertificate);
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("ID-kaardi sertifikaadid ei kehti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIFPjCCBCagAwIBAgIQR+Ll9rRaHYFVJ7iJMDws3DANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTE1MDQxMDExNDgyNVoXDTIwMDQwODIwNTk1OVowgZkxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxFzAVBgNVBAsMDmF1dGhlbnRpY2F0aW9uMSUwIwYDVQQDDBxWw4RSTklDSyxLUsOVw5VULDQ4ODEyMDQwMTM4MREwDwYDVQQEDAhWw4RSTklDSzEQMA4GA1UEKgwHS1LDlcOVVDEUMBIGA1UEBRMLNDg4MTIwNDAxMzgwggEhMA0GCSqGSIb3DQEBAQUAA4IBDgAwggEJAoIBAJY5+lz6jUd9z1MnCSXQ4adN/5foi2nNvBlhfzL+cENjd0qCMFadNw0sGrj2T996d2/kG6D629UPkSthhT78HRyguumrc+dfqCCpF8ufCtzvFrEqLrOrgy6CXp85ha008H/jDDrl36UAX5rBYjpNrGrf0gVOjFhwHwNWEkoqWa8SD7nNruBlV6uV1U9Y9cjCiY+PGE2VDHvVoEhtvpEDcYPqItoawlTm3zy1G17hhFrjWV14Cz/MFTfe1PqssAGzwuK4S1b7NALhWGj0BeVJZjgq3EhWZLGxNHbN/0BMD541iwvS4t6Ibxi/WgPXP4HLv5sp7AEm4+ZY0HrFI8mE4ukCAwEAAaOCAa0wggGpMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgSwMIGZBgNVHSAEgZEwgY4wgYsGCisGAQQBzh8DAQEwfTBYBggrBgEFBQcCAjBMHkoAQQBpAG4AdQBsAHQAIAB0AGUAcwB0AGkAbQBpAHMAZQBrAHMALgAgAE8AbgBsAHkAIABmAG8AcgAgAHQAZQBzAHQAaQBuAGcALjAhBggrBgEFBQcCARYVaHR0cDovL3d3dy5zay5lZS9jcHMvMCMGA1UdEQQcMBqBGGtyb290LnZhcm5pY2suMUBlZXN0aS5lZTAdBgNVHQ4EFgQU9s+9iXt8bwXl2jyo7381B0icwoswIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCIGCCsGAQUFBwEDBBYwFDAIBgYEAI5GAQEwCAYGBACORgEEMB8GA1UdIwQYMBaAFEG2/sWxsbRTE4z6+mLQNG1tIjQKMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZXN0ZWlkMjAxMS5jcmwwDQYJKoZIhvcNAQELBQADggEBAGKybuo83mts8buwXeW45GemQeWSD0F35qC2QUK39+vPsHr0iZlQ4VNnEC2Bv4/0Fp93PLtYs0aOEaPYffM70TY2zCzOqNZhuB4ewMMHrqoypFuaAB8TjgDE4olBfI0YvPXoBXmfZqj9tElvZEQK7HpZuYudyz0nmmRdGswIClphqYhFDVEKGcMrvAfw+1hyKFYsSliL5VpMuPWY2o/70xXF6AnKv8zQlrpaZn/4DaEKJywbFO10A7KZgRE1Dje6d3js+JeWYO2D+zApyAYgeHMr7MBYhDiMI8Fsk1P80ueL68vWXGqcoIlD+zMxa3xRPCQxxJM/N1heZXeQhSjQ2Rc=, tara.webeid.auth_token.signature=");
        assertWarningIsLogged("Token validation was interrupted:");
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate has expired");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_CERT_EXPIRED)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateNotYetValid_Fails() throws CertificateEncodingException {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        X509Certificate certificate = loadCertificateFromResource(NOT_YET_VALID_CERT_PATH);
        String base64EncodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        WebEidData body = createRequestBody();
        body.getAuthToken().setUnverifiedCertificate(base64EncodedCertificate);
        given()
                .body(body)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("ID-kaardi sertifikaadid ei kehti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIDhTCCAm0CFDKUIdM1Dd0ogPQbFsB5H4LRMJTcMA0GCSqGSIb3DQEBCwUAMH0xCzAJBgNVBAYTAkVFMQ0wCwYDVQQIDARURVNUMQ4wDAYDVQQHDAVURVNUIDENMAsGA1UECgwEVEVTVDENMAsGA1UECwwEVEVTVDENMAsGA1UEAwwEVEVTVDEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbTAiGA8yMDcyMTIyODA4MDk1NFoYDzIwNzcxMjI4MDgwOTU0WjB9MQswCQYDVQQGEwJFRTENMAsGA1UECAwEVEVTVDEOMAwGA1UEBwwFVEVTVCAxDTALBgNVBAoMBFRFU1QxDTALBgNVBAsMBFRFU1QxDTALBgNVBAMMBFRFU1QxIjAgBgkqhkiG9w0BCQEWE2V4YW1wbGVAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK4YH45a9WVapQ99qHJpD33D4A+cVGvrre6US4fuLivod1Z6V/p2wbf482kxNOkDQn87gtYGQnC8BH6OFpIpFSqJQfdhX/C513C/De5zjtlay8QNraaAJezAFi4IjpKeWLt7hu5GB403mSbJroyW+JzcEmnmWDE11MOFAxCDa8d9tFTuKRzEBwZjq70W++zr2DfSODkTzKjOarRTqZVQBTpyevF6x+Lvs02W4iRlIOvjCGNPT1YRcJ6Atrb+rZlON021lYen+1ZIoTt8xj7JVOuOb0AbEDzl2DYnOuhGzOaUuxGAigGXoT2DrDPLOZE66Jvy7yaXXhHFlPLQns45yzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJKLbM8vpkxsZNIgGE5lKOGXlDqVKD/qLNWKXaPriDiTQnP5uZTnQyjyDY9T0rwONTK8W/TkFgOO7olACOLg4GHfqsqGn2WuULQRzvLma2kDGXnPTzOXyPApZ4EckEfROaqOTqNAq051+cs/sOm7fKlr8ItkP0JGcil+kjWfQlekxhGLWGz2zvt8FXlaDKGbeihgMIEgAnHhpS3zy0epQyR4lo4G7upSUF0avNNlRbKgFgKts37BcjErkjgIZBbXJA/j14k9HbZCzDZfyjCLZEWpzxOb6a0tu9jisBLTay7PLHJHJE7Cmet5i+zfVSWPYWn9jpzoXRnZheKF+kx8kEo=, tara.webeid.auth_token.signature=");
        assertWarningIsLogged("Token validation was interrupted:");
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate is not yet valid");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_CERT_NOT_YET_VALID)");
    }

    @Test
    @DirtiesContext
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_DISABLED")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspDisabled_Success() {
        configurationProperties.setOcspEnabled(false); // TODO AUT-857
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = getSession(mockSessionFilter);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("38001085718", result.getIdCode());
        assertEquals("JAAK-KRISTJAN", result.getFirstName());
        assertEquals("JÕEORG", result.getLastName());
        assertEquals("1980-01-08", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertNull(result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertInfoIsLogged("Skipping OCSP validation because OCSP is disabled.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspEnabled_Success() {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID2018", CertificateStatus.GOOD, "/esteid2018");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = getSession(mockSessionFilter);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("38001085718", result.getIdCode());
        assertEquals("JAAK-KRISTJAN", result.getFirstName());
        assertEquals("JÕEORG", result.getLastName());
        assertEquals("1980-01-08", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertNull(result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_withEmail_Success() {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID2018", CertificateStatus.GOOD, "/esteid2018");
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .clientAllowedScopes(List.of("email", "openid"))
                .requestedScopes(List.of("email", "openid"))
                .authenticationResult(new TaraSession.IdCardAuthenticationResult())
                .nonce(new ChallengeNonce(TEST_NONCE, ZonedDateTime.now().plus(Duration.ofMinutes(5))))
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = getSession(mockSessionFilter);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("38001085718", result.getIdCode());
        assertEquals("JAAK-KRISTJAN", result.getFirstName());
        assertEquals("JÕEORG", result.getLastName());
        assertEquals("1980-01-08", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertEquals("jaak-kristjan.joeorg@eesti.ee", result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_RevokedCertificate_FailsOcspCheck() {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID2018", new RevokedStatus(new Date(), CRLReason.unspecified), "/esteid2018");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("ID-kaardi sertifikaadid on peatatud või tühistatud. Palun pöörduge Politsei- ja Piirivalveameti teenindusse."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Invalid certificate status <REVOKED> received");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_REVOKED)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnknownCertificate_FailsOcspCheck() {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID2018", new UnknownStatus(), "/esteid2018");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(400)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(400))
                .body("error", equalTo("Bad Request"))
                .body("message", equalTo("ID-kaardi sertifikaadi staatus on teadmata."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertErrorIsLogged(ErrorHandler.class, "User exception: Invalid certificate status <UNKNOWN> received");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_UNKNOWN)");
    }

    @Disabled("TODO: AUT-1164 Fails in Jenkins")
    @Test
    @DirtiesContext
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_FAILOVER_CONF")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspResponse404WithFallbackService_Success() {
        // Issuer 'TEST of ESTEID2018' is removed from main OCSP list to fall back to 'fallback-ocsp' configuration.
        List<AuthConfigurationProperties.Ocsp> ocsps = configurationProperties.getOcsp().stream()
                .filter(e -> !e.getUrl().equals("https://localhost:9877/esteid2018"))
                .collect(Collectors.toList());
        configurationProperties.setOcsp(ocsps);
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID-SK 2018", CertificateStatus.GOOD, "/ocsp");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = getSession(mockSessionFilter);
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals("38001085718", result.getIdCode());
        assertEquals("JAAK-KRISTJAN", result.getFirstName());
        assertEquals("JÕEORG", result.getLastName());
        assertEquals("1980-01-08", result.getDateOfBirth().toString());
        assertEquals("EE", result.getCountry());
        assertNull(result.getEmail());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=http://aia.demo.sk.ee/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_CA_WHITELIST")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponderCertificateIssuerNotTrusted_Error() {
        setupMockOcspResponseForSingleTest("CN=WRONG CN", CertificateStatus.GOOD, "/esteid2018");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(500))
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertErrorIsLogged(ErrorHandler.class, "Server encountered an unexpected error: OCSP validation failed: Issuer certificate with CN 'WRONG CN' is not a trusted certificate!");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_VALID_SIG")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponderCertificateIssuerDifferentFromUserCertificateIssuer_Error() {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID-SK 2011", CertificateStatus.GOOD, "/esteid2018");
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(500))
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("OCSP certificate validation. Serialnumber=<96454726563488174362096220658227824995>, SubjectDN=<SERIALNUMBER=PNOEE-38001085718, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", SURNAME=JÕEORG, GIVENNAME=JAAK-KRISTJAN, C=EE>, issuerDN=<CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE>");
        assertErrorIsLogged(ErrorHandler.class, "Server encountered an unexpected error: OCSP validation failed: In case of AIA OCSP, the OCSP responder certificate must be issued by the authority that issued the user certificate. Expected issuer: 'CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE', but the OCSP responder signing certificate was issued by 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE'");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP response: 200", "http.response.status_code=200, http.response.body.content=");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_VALID_RESPONSE")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponseBodyMissing_Error() {
        wireMockServer.stubFor(WireMock.post("/esteid2018")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withTransformer("ocsp", "ignore", true)
                        .withHeader("Content-Type", "application/ocsp-response")));
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(500)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(500))
                .body("error", equalTo("Internal Server Error"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "Server encountered an unexpected error: OCSP validation failed: malformed response: no response data found");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertMessageWithMarkerIsLoggedOnce(OCSPValidator.class, INFO, "OCSP request", "http.request.method=GET, url.full=https://localhost:9877/esteid2018, http.request.body.content={\"http.request.body.content\":");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_VALID_RESPONSE")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspServiceNotAvailable_Error() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/esteid2018"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(2000)));
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();

        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/login")
                .then()
                .assertThat()
                .statusCode(502)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .body("status", equalTo(502))
                .body("error", equalTo("Bad Gateway"))
                .body("message", equalTo("ID-kaardi sertifikaadi kehtivuse info küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "Service not available: Service returned HTTP status code 404");
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate=MIIEDTCCA26gAwIBAgIQSJCBLo408CZcysmwbeFJYzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDI1NloXDTI5MDUwMjEwNDI1NlowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARjRfVZiep2g1kkUzxTcP0n8OIeXcBv67y5I/d91i5t7PzeG0oIn4YirFA2jpigzVpp0behIEn+PxonDpd5kRBrLYJKi2kxrf/aqRtihkVSxRWc+tepYp9UU3KMz4Ktuj2jggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFMbYLLR9I+bizugSrwcdnRKiqvlTMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgGtZvDpqYbH1lSpVLmZ7I8LMlpLO0No1bnTucV5+g3SVvsMR1LI9+L/tDmbPP6f7nAb3ovPAV7BNUQfJRR79G+ijwJCAKKkclADtEOMeSH5kLLw5429rFzHyQeYxp9Tz8c7raiat/OhNMwWnpZ0EE6kUSJ+/j/QLlimDsCv/RVEWZzA9UMJ, tara.webeid.auth_token.signature=");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=IDC_OCSP_NOT_AVAILABLE)");
    }

    private MockSessionFilter buildDefaultSessionFilter() {
        return MockSessionFilter
                .withTaraSession()
                .authenticationResult(new TaraSession.IdCardAuthenticationResult())
                .nonce(new ChallengeNonce(TEST_NONCE, ZonedDateTime.now().plus(Duration.ofMinutes(5))))
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();
    }

    @SneakyThrows
    private void setupMockOcspResponseForSingleTest(String issuerDn, CertificateStatus certificateStatus, String stubUrl) {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair certKeyPair = rsa.generateKeyPair();
        X509Certificate ocspResponderCert = generateOcspResponderCertificate("CN=MOCK OCSP RESPONDER, C=EE", certKeyPair, responderKeys, issuerDn).getCertificate();
        ocspResponseTransformer.setSignerKey(certKeyPair.getPrivate());
        setUpMockOcspResponse(MockOcspResponseParams.builder()
                .ocspServer(wireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(certificateStatus)
                .responseId("CN=MOCK OCSP RESPONDER")
                .ocspConf(ocspConfiguration)
                .responderCertificate(ocspResponderCert)
                .build(), stubUrl);
    }

    private WebEidData createRequestBody() {
        WebEidData body = new WebEidData();
        body.setAuthToken(createAuthToken());
        body.setExtensionVersion("2.2.0");
        body.setNativeAppVersion("2.0.2+565");
        body.setStatusDurationMs("200");
        return body;
    }

    @SneakyThrows
    private WebEidAuthToken createAuthToken() {
        WebEidAuthToken authToken = new WebEidAuthToken();
        authToken.setUnverifiedCertificate(base64EncodedUserCertificate);
        authToken.setSignature(getSignedAuthenticationValue(usersPrivateKey));
        authToken.setAlgorithm("ES384");
        authToken.setFormat("web-eid:1:0");
        return authToken;
    }

    @SneakyThrows
    private static X509Certificate loadCertificateFromResource(String resourcePath) {
        try (InputStream inputStream = IdCardLoginControllerTest.class.getClassLoader().getResourceAsStream(resourcePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

    @SneakyThrows
    private static PrivateKey readPrivateKey(String privateKeyPath, String keyPassword) {
        Object keyPair;
        try(InputStream is = IdCardLoginControllerTest.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            Reader reader = new BufferedReader(new InputStreamReader(is));
            PEMParser keyReader = new PEMParser(reader);
            keyPair = keyReader.readObject();
            keyReader.close();
        }

        BouncyCastleProvider securityProvider = new BouncyCastleProvider();
        Security.addProvider(securityProvider);
        PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) keyPair;
        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                .setProvider(securityProvider)
                .build(keyPassword.toCharArray());
        PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(pkcs8Prov);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("SunEC");
        return converter.getPrivateKey(privateKeyInfo);
    }

    @SneakyThrows
    private String getSignedAuthenticationValue(PrivateKey privateKey) {
        String origin = configurationProperties.getSiteOrigin().toString();
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        byte[] originDigest = md.digest(origin.getBytes());
        byte[] nonceDigest = md.digest(TEST_NONCE.getBytes());
        byte[] authValue = getUnsignedAuthenticationValue(originDigest, nonceDigest);
        return signAuthenticationValue(privateKey, authValue);
    }

    @SneakyThrows
    private String signAuthenticationValue(PrivateKey privateKey, byte[] authValue) {
        Signature ecdsaSign = Signature.getInstance("SHA384withECDSAinP1363Format");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(authValue);
        byte[] signature = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    @SneakyThrows
    private byte[] getUnsignedAuthenticationValue(byte[] originDigest, byte[] nonceDigest) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(originDigest);
        outputStream.write(nonceDigest);
        return outputStream.toByteArray();
    }

    private TaraSession getSession(MockSessionFilter mockSessionFilter) {
        return sessionRepository.findById(mockSessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
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
}
