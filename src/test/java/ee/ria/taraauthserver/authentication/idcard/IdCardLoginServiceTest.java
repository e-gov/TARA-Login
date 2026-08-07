package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdCardLoginServiceTest {

    private AuthTokenValidator authTokenValidator;
    private ChallengeNonceStore nonceStore;
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;
    private AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private AuthTokenValidatorResolver authTokenValidatorResolver;
    private StatisticsLogger statisticsLogger;

    private IdCardLoginService service;

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        authTokenValidator = mock(AuthTokenValidator.class);
        nonceStore = mock(ChallengeNonceStore.class);
        statisticsLogger = mock(StatisticsLogger.class);
        configurationProperties = mock(AuthConfigurationProperties.IdCardAuthConfigurationProperties.class);
        filterForEidasProxy = mock(AuthConfigurationProperties.FilterForEidasProxy.class);
        authTokenValidatorResolver = mock(AuthTokenValidatorResolver.class);

        service = new IdCardLoginService(
                configurationProperties,
                filterForEidasProxy,
                nonceStore,
                statisticsLogger,
                authTokenValidatorResolver
        );
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void attemptLogin_whenValidationSucceeds_usesResolvedValidator() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator);

        service.attemptLogin(loginTestData.data(), loginTestData.taraSession());

        verify(authTokenValidatorResolver).resolve(loginTestData.client());
        verify(authTokenValidator).validate(any(), any());
    }

    @Test
    void attemptLogin_eidasProxyClientAndAllowedPolicyOid_succeeds() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator);
        givenEidasProxyClient(loginTestData, Set.of("1.3.6.1.4.1.51361.1.2.1"));

        service.attemptLogin(loginTestData.data(), loginTestData.taraSession());

        verify(loginTestData.taraSession()).setState(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

    @Test
    void attemptLogin_eidasProxyClientAndDisallowedPolicyOid_failsWithCertForbidden() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator);
        givenEidasProxyClient(loginTestData, Set.of("1.2.3.4"));

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> service.attemptLogin(loginTestData.data(), loginTestData.taraSession()));

        assertEquals(ErrorCode.IDC_CERT_FORBIDDEN, exception.getErrorCode());
    }

    @Test
    void attemptLogin_successfulAuthentication_storesCertificatePolicyOidsForStatisticsLogging() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator);

        service.attemptLogin(loginTestData.data(), loginTestData.taraSession());

        verify(loginTestData.authenticationResult()).setCertificatePolicyOids(List.of(
                "1.3.6.1.4.1.51361.1.2.1",
                "0.4.0.2042.1.2"
        ));
    }

    @Test
    void attemptLogin_disallowedPolicyOid_storesCertificatePolicyOidsForFailureStatisticsLogging() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator);
        givenEidasProxyClient(loginTestData, Set.of("1.2.3.4"));
        givenSuccessfulOcspValidation(loginTestData);

        assertThrows(BadRequestException.class,
                () -> service.attemptLogin(loginTestData.data(), loginTestData.taraSession()));

        verify(loginTestData.authenticationResult()).setCertificatePolicyOids(List.of(
                "1.3.6.1.4.1.51361.1.2.1",
                "0.4.0.2042.1.2"
        ));
        verify(statisticsLogger).logExternalTransaction(any(), any(IdCardLoginService.OcspInfo.class));
    }

    @Test
    void attemptLogin_eidasProxyClientAndCertificateWithoutPolicies_failsWithCertForbiddenAndStoresEmptyPolicyList() throws Exception {
        LoginTestData loginTestData = givenSuccessfulLoginValidation(authTokenValidator, generateCertificateWithoutPolicies());
        givenEidasProxyClient(loginTestData, Set.of("1.3.6.1.4.1.51361.1.2.1"));

        BadRequestException exception = assertThrows(BadRequestException.class,
                () -> service.attemptLogin(loginTestData.data(), loginTestData.taraSession()));

        assertEquals(ErrorCode.IDC_CERT_FORBIDDEN, exception.getErrorCode());
    }

    private LoginTestData givenSuccessfulLoginValidation(AuthTokenValidator validator) throws Exception {
        return givenSuccessfulLoginValidation(validator, loadCertificate());
    }

    private LoginTestData givenSuccessfulLoginValidation(AuthTokenValidator validator, X509Certificate certificate) throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        TaraSession.Client client = mock(TaraSession.Client.class);
        TaraSession.IdCardAuthenticationResult authenticationResult = mock(TaraSession.IdCardAuthenticationResult.class);
        WebEidAuthToken authToken = mock(WebEidAuthToken.class);
        ValidationInfo validationInfo = mock(ValidationInfo.class);
        ChallengeNonce challengeNonce = mock(ChallengeNonce.class);

        when(filterForEidasProxy.getClientId()).thenReturn("eidas-client");
        when(taraSession.getOriginalClient()).thenReturn(client);
        when(client.getClientId()).thenReturn("regular-client");
        when(nonceStore.getAndRemove()).thenReturn(challengeNonce);
        when(challengeNonce.getBase64EncodedNonce()).thenReturn("nonce");
        when(validator.validate(any(), any())).thenReturn(validationInfo);
        when(validationInfo.subjectCertificate()).thenReturn(certificate);
        when(configurationProperties.getOcsp()).thenReturn(mock(AuthConfigurationProperties.Ocsp.class));
        when(configurationProperties.getOcsp().isEnabled()).thenReturn(false);
        when(taraSession.getAuthenticationResult()).thenReturn(authenticationResult);
        when(authTokenValidatorResolver.resolve(client)).thenReturn(validator);

        IdCardLoginController.WebEidData data = new IdCardLoginController.WebEidData();
        data.setAuthToken(authToken);
        return new LoginTestData(taraSession, client, authenticationResult, validationInfo, data);
    }

    private void givenEidasProxyClient(LoginTestData loginTestData, Set<String> allowedPolicyOids) {
        when(loginTestData.client().getClientId()).thenReturn("eidas-client");
        when(filterForEidasProxy.getAllowedPolicyOids()).thenReturn(allowedPolicyOids.stream()
                .map(ASN1ObjectIdentifier::new)
                .collect(java.util.stream.Collectors.toSet()));
    }

    private void givenSuccessfulOcspValidation(LoginTestData loginTestData) throws Exception {
        RevocationInfo revocationInfo = mock(RevocationInfo.class);
        OCSPReq ocspReq = mock(OCSPReq.class);
        OCSPResp ocspResp = mock(OCSPResp.class);
        when(ocspReq.getEncoded()).thenReturn(new byte[]{1});
        when(ocspResp.getEncoded()).thenReturn(new byte[]{2});
        when(revocationInfo.ocspResponderUri()).thenReturn(URI.create("https://ocsp.example.test"));
        when(revocationInfo.ocspResponseAttributes()).thenReturn(Map.of(
                RevocationInfo.KEY_OCSP_REQUEST, ocspReq,
                RevocationInfo.KEY_OCSP_RESPONSE, ocspResp,
                RevocationInfo.KEY_REQUEST_DURATION, Duration.ofMillis(10)
        ));
        when(loginTestData.validationInfo().revocationInfoList()).thenReturn(List.of(revocationInfo));
        when(configurationProperties.getOcsp().isEnabled()).thenReturn(true);
    }

    private record LoginTestData(
            TaraSession taraSession,
            TaraSession.Client client,
            TaraSession.IdCardAuthenticationResult authenticationResult,
            ValidationInfo validationInfo,
            IdCardLoginController.WebEidData data
    ) {
    }

    private static X509Certificate loadCertificate() throws Exception {
        try (InputStream inputStream = Files.newInputStream(Path.of("src/test/resources/id-card/38001085718(TEST_of_ESTEID2018).pem"))) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }

    private static X509Certificate generateCertificateWithoutPolicies() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X500Name subject = new X500Name("CN=test");
        Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
        Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(1)));
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
