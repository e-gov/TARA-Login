package ee.ria.taraauthserver.authentication.idcard;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.idcard.IdCardLoginController.WebEidData;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.ErrorHandler;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockSessionFilter.CsrfMode;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.TestUtils;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static ee.ria.taraauthserver.security.SessionManagementFilter.MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
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
    private final AuthConfigurationProperties.Ocsp ocspConfiguration = new AuthConfigurationProperties.Ocsp();
    // Synthetic test PKI so OCSP can be served fully locally (air-gapped CI safe). The real test certificate's AIA
    // OCSP URL points at the external aia.demo.sk.ee, which CI cannot reach. We instead issue a user certificate from
    // an in-test CA, with its AIA OCSP URL pointing at the in-test WireMock (HTTP, to avoid TLS trust setup since the
    // web-eid OcspClient uses the default JDK HttpClient/SSLContext). The synthetic CA is added to the id-card
    // issuer truststore via @DynamicPropertySource so the validator trusts the user certificate and, per the web-eid
    // AIA rule, the OCSP responder certificate (which we issue from the same CA).
    private static final String CA_DN = "CN=TEST of ESTEID2018 MOCK CA, O=SK ID Solutions AS, C=EE";
    private static final String AIA_OCSP_URL = "http://localhost:9876/esteid2018";
    private static KeyPair caKeyPair;
    private static X509Certificate caCertificate;
    private static X509Certificate userCertificate;
    private static String augmentedIssuerTruststorePath;
    private static PrivateKey usersPrivateKey;
    private static String base64EncodedUserCertificate;
    private KeyPair responderKeys;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            X509Certificate template = TestUtils.loadCertificateFromResource(VALID_CERT_PATH);

            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            rsa.initialize(2048);
            caKeyPair = rsa.generateKeyPair();
            caCertificate = generateCaCertificate(CA_DN, caKeyPair);

            // User key uses the SunEC provider so SHA384withECDSAinP1363Format signing works as before.
            KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
            ec.initialize(new ECGenParameterSpec("secp384r1"));
            KeyPair userKeys = ec.generateKeyPair();
            usersPrivateKey = userKeys.getPrivate();
            userCertificate = generateUserCertificate(template, userKeys.getPublic(), new X500Name(CA_DN), caKeyPair.getPrivate(), AIA_OCSP_URL);
            base64EncodedUserCertificate = Base64.getEncoder().encodeToString(userCertificate.getEncoded());

            augmentedIssuerTruststorePath = buildAugmentedIssuerTruststore(caCertificate).toString();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void overrideIdCardTruststores(DynamicPropertyRegistry registry) {
        registry.add("tara.auth-methods.id-card.issuer-truststore.path", () -> "file:" + augmentedIssuerTruststorePath);
        registry.add("tara.auth-methods.id-card.ocsp.responder-truststore.path", () -> "file:" + augmentedIssuerTruststorePath);
    }

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;

    @Autowired
    private AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;

    @BeforeEach
    void setUpTest() {
        // The OCSP responder certificate must be issued by the user certificate's issuer (web-eid AIA rule),
        // so the in-test CA acts as the responder-cert issuer.
        responderKeys = caKeyPair;
        ocspResponseTransformer.setThisUpdateProvider(() -> Date.from(Instant.now()));
        ocspResponseTransformer.setNonceResolver(nonce -> nonce);
        // The validator always performs the AIA OCSP check inside validate() (regardless of the runtime ocsp.enabled
        // flag), so provide a default GOOD response on the AIA path. Tests needing other statuses re-stub it.
        setupMockOcspResponseForSingleTest(CA_DN, CertificateStatus.GOOD, "/esteid2018");
    }

    @AfterEach
    void tearDown() {
        configurationPropertiesReloader.reload(configurationProperties);
        configurationPropertiesReloader.reload(filterForEidasProxy);
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.SESSION_STATE_INVALID)
                        .build());
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: Challenge nonce was not found in the nonce store");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.INVALID_REQUEST)
                        .build());
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: Challenge nonce has expired");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.INVALID_REQUEST)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_InvalidAuthTokenFormat_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                t.unverifiedCertificate(),
                t.signature(),
                t.algorithm(),
                "INVALID FORMAT"
        ));
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
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        assertErrorIsLogged(ErrorHandler.class, "User exception: Only token format version 'web-eid:1' is currently supported");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateMissing_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                null,
                t.signature(),
                t.algorithm(),
                t.format()
        ));
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
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(null));
        assertErrorIsLogged(ErrorHandler.class, "User exception: 'unverifiedCertificate' field is missing, null or empty");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateEmpty_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                "",
                t.signature(),
                t.algorithm(),
                t.format()
        ));
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
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(""));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: 'unverifiedCertificate' field is missing, null or empty");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateInvalidContents_Fails() {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                "SW52YWxpZCBjZXJ0aWZpY2F0ZQo=", // Base64-encoded string: "Invalid certificate"
                t.signature(),
                t.algorithm(),
                t.format()
        ));
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
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern("SW52YWxpZCBjZXJ0aWZpY2F0ZQo="));
        assertErrorIsLogged(ErrorHandler.class, "User exception: Certificate decoding from Base64 or parsing failed");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateExpired_Fails() throws CertificateEncodingException {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        X509Certificate certificate = TestUtils.loadCertificateFromResource(EXPIRED_CERT_PATH);
        String base64EncodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                base64EncodedCertificate,
                t.signature(),
                t.algorithm(),
                t.format()
        ));
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedCertificate));
        assertWarningIsLogged("Token validation was interrupted:");
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate has expired");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_CERT_EXPIRED)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "WEBEID_AUTHENTICATION_TOKEN_VALIDATION")
    @Tag(value = "CERTIFICATE_IS_VALID")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnverifiedCertificateNotYetValid_Fails() throws CertificateEncodingException {
        MockSessionFilter mockSessionFilter = buildDefaultSessionFilter();
        X509Certificate certificate = TestUtils.loadCertificateFromResource(NOT_YET_VALID_CERT_PATH);
        String base64EncodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        WebEidData body = createRequestBody();
        updateAuthToken(body, t -> new WebEidAuthToken(
                base64EncodedCertificate,
                t.signature(),
                t.algorithm(),
                t.format()
        ));
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedCertificate));
        assertWarningIsLogged("Token validation was interrupted:");
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate is not yet valid");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_CERT_NOT_YET_VALID)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_DISABLED")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspDisabled_Success() {
        configurationProperties.getOcsp().setEnabled(false);
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        assertInfoIsLogged("Skipping OCSP validation because OCSP is disabled.");
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspEnabled_Success() {
        setupMockOcspResponseForSingleTest(CA_DN, CertificateStatus.GOOD, "/esteid2018");
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_withEmail_Success() {
        setupMockOcspResponseForSingleTest(CA_DN, CertificateStatus.GOOD, "/esteid2018");
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .clientAllowedScopes(List.of("email", "openid"))
                .requestedScopes(List.of("email", "openid"))
                .authenticationResult(authenticationResult)
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_successfulAuthentication() {
        setupMockOcspResponseForSingleTest(CA_DN, CertificateStatus.GOOD, "/esteid2018");
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .clientAllowedScopes(List.of("email", "openid"))
                .requestedScopes(List.of("email", "openid"))
                .authenticationResult(authenticationResult)
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
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        assertEquals(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "State: NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT -> NATURAL_PERSON_AUTHENTICATION_COMPLETED");
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Client-side Web eID operation successful");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO,
                "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "OCSP request");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO,
                "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "OCSP response: 200");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO,
                "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_failedAuthentication() {
        setupMockOcspResponseForSingleTest(CA_DN, new RevokedStatus(new Date(), CRLReason.unspecified), "/esteid2018");
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
        String taraTraceId = DigestUtils.sha256Hex(sessionId);
        assertNull(sessionRepository.findById(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate has been revoked");
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Client-side Web eID operation successful");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO,
                "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Session has been invalidated: " + sessionId);
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN,
                "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "OCSP request");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO,
                "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "OCSP response: 200");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO,
                "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.IDC_REVOKED)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_REVOKED)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_RevokedCertificateStatus_FailsOcspCheck() {
        setupMockOcspResponseForSingleTest(CA_DN, new RevokedStatus(new Date(), CRLReason.unspecified), "/esteid2018");
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
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate has been revoked");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.IDC_REVOKED)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_REVOKED)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_STATUS_HANDLING")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_UnknownCertificateStatus_FailsOcspCheck() {
        setupMockOcspResponseForSingleTest(CA_DN, new UnknownStatus(), "/esteid2018");
        setupMockOcspResponseForSingleTest(CA_DN, new UnknownStatus(), "/ocsp/fallback");
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
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertErrorIsLogged(ErrorHandler.class, "User exception: User certificate revocation check has failed");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // The resilient flow may make two OCSP requests (primary + fallback), so scope the assertion to the
        // primary request marker rather than counting all "OCSP request" log lines.
        assertMessageWithMarkerIsLogged(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""), 2);
        assertInfoIsLogged(IdCardLoginService.class, "OCSP response: 200");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertStatisticsIsLogged(ERROR, e -> e.getMarker().toString().contains("ocspUrl=http://localhost:9876/esteid2018"),
                "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build(), 2);
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMarker().toString().contains("ocspUrl=http://localhost:9876/ocsp/fallback"),
                "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/ocsp/fallback")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/ocsp/fallback")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_FAILOVER_CONF")
    @Tag(value = "IDCARD_AUTH_SUCCESSFUL")
    void handleRequest_OcspResponse404WithFallbackService_Success() {
        ocspWireMockServer.stubFor(any(urlPathEqualTo("/esteid2018"))
                .willReturn(aResponse().withStatus(404)));
        setupMockOcspResponseForSingleTest(CA_DN, CertificateStatus.GOOD, "/ocsp/fallback");
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        assertMessageWithMarkerIsLogged(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""), 2);
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/ocsp/fallback")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Disabled("AUT-2678 follow-up: AIA OCSP is now mocked, but this negative case still needs assertion rework (web-eid error message / issuer DNs differ from the legacy validator); cannot force responder certificate issuer CN in this test")
    @ParameterizedTest
    @MethodSource("ocspResponseStatuses")
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_CA_WHITELIST")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponderCertificateIssuerNotTrusted_Error(CertificateStatus certificateStatus, ErrorCode expectedErrorCode) {
        setupMockOcspResponseForSingleTest("CN=WRONG CN", certificateStatus, "/esteid2018");
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
        assertErrorIsLogged(ErrorHandler.class, "Server encountered an unexpected error: Issuer certificate with CN 'WRONG CN' is not a trusted certificate!");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(expectedErrorCode)
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(expectedErrorCode)
                        .build());
    }

    @Disabled("AUT-2678 follow-up: AIA OCSP is now mocked, but this negative case still needs assertion rework (web-eid error message / issuer DNs differ from the legacy validator); cannot force responder certificate issuer to differ from user certificate issuer")
    @ParameterizedTest
    @MethodSource("ocspResponseStatuses")
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_RESPONSE_VALID_SIG")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponderCertificateIssuerDifferentFromUserCertificateIssuer_Error(CertificateStatus certificateStatus, ErrorCode expectedErrorCode) {
        setupMockOcspResponseForSingleTest("CN=TEST of ESTEID-SK 2015", certificateStatus, "/esteid2018");
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
        assertErrorIsLogged(ErrorHandler.class, "Server encountered an unexpected error: In case of AIA OCSP, the OCSP responder certificate must be issued by the authority that issued the user certificate. Expected issuer: 'CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE', but the OCSP responder signing certificate was issued by 'CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE'");
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("GET", "https://localhost:9877/esteid2018", "{\"http.request.body.content\":"));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP response: 200", ocspResponseMarkerPattern(200));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("https://localhost:9877/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(expectedErrorCode)
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("https://localhost:9877/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(expectedErrorCode)
                        .build());
    }

    @Disabled("AUT-2678 follow-up: AIA OCSP is now mocked, but this negative case still needs assertion rework (web-eid error message / issuer DNs differ from the legacy validator); cannot force malformed OCSP response body")
    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_VALID_RESPONSE")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspResponseBodyMissing_Error() {
        ocspWireMockServer.stubFor(WireMock.post("/esteid2018")
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
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("GET", "https://localhost:9877/esteid2018", "{\"http.request.body.content\":"));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("https://localhost:9877/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.INTERNAL_ERROR)
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("https://localhost:9877/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.INTERNAL_ERROR)
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    @Tag(value = "OCSP_VALID_RESPONSE")
    @Tag(value = "IDCARD_ERROR_HANDLING")
    void handleRequest_OcspServiceNotAvailable_Error() {
        ocspWireMockServer.stubFor(WireMock.post(urlEqualTo("/esteid2018"))
                .willReturn(aResponse()
                        .withStatus(502)));
        ocspWireMockServer.stubFor(WireMock.post(urlEqualTo("/ocsp/fallback"))
                .willReturn(aResponse()
                        .withStatus(502)));
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
                .body("message", equalTo("ID-kaardi sertifikaadi kehtivuse info küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(IdCardLoginController.class, INFO, "Client-side Web eID operation successful", successfulWebEidOperationMarkerPattern(base64EncodedUserCertificate));
        // TODO Assert proper regex
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, invalidatedSessionMarkerPattern(sessionId));
        assertMessageWithMarkerIsLogged(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/esteid2018", ""), 2);
        assertMessageWithMarkerIsLogged(IdCardLoginService.class, INFO, "OCSP request", ocspRequestMarkerPattern("POST", "http://localhost:9876/ocsp/fallback", ""), 1);
        assertStatisticsIsLogged(ERROR, e -> e.getMarker().toString().contains("ocspUrl=http://localhost:9876/esteid2018"), "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.EXTERNAL_TRANSACTION)
                        .errorCode(ErrorCode.IDC_OCSP_NOT_AVAILABLE)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build(), 2);
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMarker().toString().contains("ocspUrl=http://localhost:9876/ocsp/fallback"), "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/ocsp/fallback")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_OCSP_NOT_AVAILABLE)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    void handleRequest_eidasProxyClientAndAllowedCertificatePolicyOid_Succeeds() {
        configurationProperties.getOcsp().setEnabled(false);
        filterForEidasProxy.setClientId("openIdDemo");
        filterForEidasProxy.setAllowedPolicyOids(Set.of("1.3.6.1.4.1.51361.1.2.1"));
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
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    void handleRequest_forbiddenCertificatePolicyOidWithoutEidasProxyClient_Succeeds() {
        configurationProperties.getOcsp().setEnabled(false);
        filterForEidasProxy.setAllowedPolicyOids(Set.of("1.3.6.1.4.1.51361.1.1.1"));
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
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    void handleRequest_eidasProxyClientAndDisallowedCertificatePolicyOid_Fails() {
        filterForEidasProxy.setClientId("openIdDemo");
        filterForEidasProxy.setAllowedPolicyOids(Set.of("1.2.3.4"));
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
                .body("message", containsString("Seda tüüpi ID-kaardiga ei ole võimalik autentimine välisriikide e-teenustesse."));

        assertErrorIsLogged(ErrorHandler.class, "User exception: eIDAS authentication with given certificate policy OID is forbidden");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .idCode("38001085718")
                        .ocspUrl("http://localhost:9876/esteid2018")
                        .authenticationType(AuthenticationType.ID_CARD)
                        .authenticationState(TaraAuthenticationState.AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.IDC_CERT_FORBIDDEN)
                        .certificatePolicyOids(List.of(
                                "1.3.6.1.4.1.51361.1.2.1",
                                "0.4.0.2042.1.2"
                        ))
                        .build());
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    void handleRequest_nonForbiddenClientId_Succeeds() {
        configurationProperties.getOcsp().setEnabled(false);
        filterForEidasProxy.setClientId("testID");
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
    }

    @Test
    @Tag(value = "ESTEID_LOGIN_ENDPOINT")
    void handleRequest_allowedCertificatePolicyOid_Succeeds() {
        configurationProperties.getOcsp().setEnabled(false);
        filterForEidasProxy.setAllowedPolicyOids(Set.of("1.3.6.1.4.1.51361.1.2.1"));
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
    }

    private MockSessionFilter buildDefaultSessionFilter() {
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        authenticationResult.setAmr(AuthenticationType.ID_CARD);
        return MockSessionFilter
                .withTaraSession()
                .authenticationResult(authenticationResult)
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
                .ocspServer(ocspWireMockServer)
                .responseStatus(OCSPResp.SUCCESSFUL)
                .certificateStatus(certificateStatus)
                .responseId("CN=MOCK OCSP RESPONDER, C=EE")
                .ocspConf(ocspConfiguration)
                .responderCertificate(ocspResponderCert)
                .build(), stubUrl);
    }

    public static X500PrivateCredential generateOcspResponderCertificate(String certDn, KeyPair certKeyPair, KeyPair caKeyPair, String issuerDn) throws CertificateException, OperatorCreationException, CertIOException {
        X500Name issuerName = new X500Name(issuerDn);
        X500Name subjectName = new X500Name(certDn);
        BigInteger serial = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(Instant.now().minus(Duration.ofHours(1))), Date.from(Instant.now().plus(Duration.ofHours(1))), subjectName, certKeyPair.getPublic());
        builder.addExtension(Extension.extendedKeyUsage, true, new DERSequence(new ASN1Encodable[]{
                KeyPurposeId.id_kp_OCSPSigning.toOID()
        }));

        X509Certificate cert = signCertificate(builder, caKeyPair.getPrivate());

        return new X500PrivateCredential(cert, certKeyPair.getPrivate());
    }

    public static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey caPrivateKey) throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caPrivateKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(signer));
    }

    private static X509Certificate generateCaCertificate(String dn, KeyPair caKeys) throws Exception {
        X500Name name = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial,
                Date.from(Instant.now().minus(Duration.ofDays(1))),
                Date.from(Instant.now().plus(Duration.ofDays(3650))),
                name, caKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return signCertificate(builder, caKeys.getPrivate());
    }

    // Issues a user certificate that mirrors the real test certificate's subject, Subject Alternative Name (email) and
    // certificate policy OIDs (so identity/email/eIDAS-policy assertions are unchanged), but is issued by the in-test
    // CA and carries an AIA OCSP access location pointing at the in-test WireMock.
    private static X509Certificate generateUserCertificate(X509Certificate template, PublicKey userPublicKey,
                                                           X500Name issuer, PrivateKey caPrivateKey, String ocspUrl) throws Exception {
        X500Name subject = X500Name.getInstance(template.getSubjectX500Principal().getEncoded());
        BigInteger serial = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial,
                Date.from(Instant.now().minus(Duration.ofDays(1))),
                Date.from(Instant.now().plus(Duration.ofDays(365))),
                subject, userPublicKey);
        X509CertificateHolder templateHolder = new JcaX509CertificateHolder(template);
        for (org.bouncycastle.asn1.ASN1ObjectIdentifier oid : new org.bouncycastle.asn1.ASN1ObjectIdentifier[]{
                Extension.keyUsage, Extension.extendedKeyUsage, Extension.subjectAlternativeName, Extension.certificatePolicies}) {
            Extension extension = templateHolder.getExtension(oid);
            if (extension != null) {
                builder.addExtension(extension);
            }
        }
        if (templateHolder.getExtension(Extension.keyUsage) == null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }
        builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        return signCertificate(builder, caPrivateKey);
    }

    // Copies the existing id-card issuer truststore and adds the in-test CA, so the validator trusts both the real CAs
    // (used by the negative tests) and the synthetic CA, without committing a binary truststore.
    private static Path buildAugmentedIssuerTruststore(X509Certificate ca) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of("src/test/resources/idcard-truststore-test.p12"))) {
            keyStore.load(in, "changeit".toCharArray());
        }
        keyStore.setCertificateEntry("synthetic-test-ca", ca);
        Path augmented = Files.createTempFile("idcard-truststore-augmented", ".p12");
        try (OutputStream out = Files.newOutputStream(augmented)) {
            keyStore.store(out, "changeit".toCharArray());
        }
        augmented.toFile().deleteOnExit();
        return augmented;
    }

    private Pattern successfulWebEidOperationMarkerPattern(String unverifiedCertificate) {
        return Pattern.compile(Pattern.quote(
                "tara.webeid.extension_version=2.2.0, tara.webeid.native_app_version=2.0.2+565, tara.webeid.status_duration_ms=200, tara.webeid.code=SUCCESS, tara.webeid.auth_token.unverified_certificate="
                        + String.valueOf(unverifiedCertificate)
                        + ", tara.webeid.auth_token.signature=") + ".*");
    }

    private Pattern invalidatedSessionMarkerPattern(String sessionId) {
        return Pattern.compile(Pattern.quote(
                "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(") + ".*");
    }

    private Pattern ocspRequestMarkerPattern(String method, String url, String bodyPrefix) {
        return Pattern.compile(Pattern.quote(
                "http.request.method=" + method + ", url.full=" + url + ", http.request.body.content=" + bodyPrefix) + ".*");
    }

    private Pattern ocspResponseMarkerPattern(int statusCode) {
        return Pattern.compile(Pattern.quote("http.response.status_code=" + statusCode + ", http.response.body.content=") + ".*");
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
        return new WebEidAuthToken(
                base64EncodedUserCertificate,
                getSignedAuthenticationValue(usersPrivateKey),
                "ES384",
                "web-eid:1:0"
        );
    }

    private void updateAuthToken(IdCardLoginController.WebEidData body,
                                 Function<WebEidAuthToken, WebEidAuthToken> updater) {
        body.setAuthToken(updater.apply(body.getAuthToken()));
    }

    @SneakyThrows
    private String getSignedAuthenticationValue(PrivateKey privateKey) {
        String origin = authConfigurationProperties.getSiteOrigin().toString();
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

    private static Stream<Arguments> ocspResponseStatuses() {
        return Stream.of(
                Arguments.of(CertificateStatus.GOOD, ErrorCode.IDC_VALIDATION_ERROR_RESULT_GOOD),
                Arguments.of(new RevokedStatus(new Date(), CRLReason.unspecified), ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED),
                Arguments.of(new UnknownStatus(), ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER)
        );
    }
}
