package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdCardLoginServiceTest {

    private AuthTokenValidator authTokenValidator;
    private ChallengeNonceStore nonceStore;
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;
    private AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private AuthTokenValidatorResolver authTokenValidatorResolver;
    private OcspRequestResponseLogger ocspRequestResponseLogger;
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
        ocspRequestResponseLogger = mock(OcspRequestResponseLogger.class);

        service = new IdCardLoginService(
                configurationProperties,
                filterForEidasProxy,
                nonceStore,
                statisticsLogger,
                authTokenValidatorResolver,
                ocspRequestResponseLogger
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
    void processOcspValidationResults_whenSuccessfulResponseNotLast_throwsIllegalStateException() throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        ValidationInfo validationInfo = new ValidationInfo(loadCertificate(), List.of(
                new RevocationInfo(URI.create("http://ocsp1.test"), Map.of()),
                new RevocationInfo(URI.create("http://ocsp2.test"), Map.of())));

        assertThatThrownBy(() -> service.processOcspValidationResults(validationInfo, taraSession))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Only the last response can be successful");
    }

    @Test
    void processOcspValidationResults_whenLastResponseSuccessful_updatesAuthenticationResultAndLogsStatistics() throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        when(taraSession.getAuthenticationResult()).thenReturn(authenticationResult);
        when(configurationProperties.getLevelOfAssurance()).thenReturn(LevelOfAssurance.HIGH);
        OCSPResp ocspResp = mock(OCSPResp.class);
        ValidationInfo validationInfo = new ValidationInfo(loadCertificate(), List.of(
                new RevocationInfo(URI.create("http://ocsp.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

        service.processOcspValidationResults(validationInfo, taraSession);

        assertThat(authenticationResult.getIdCode()).isEqualTo("38001085718");
        assertThat(authenticationResult.getFirstName()).isEqualTo("JAAK-KRISTJAN");
        assertThat(authenticationResult.getLastName()).isEqualTo("JÕEORG");
        assertThat(authenticationResult.getCountry()).isEqualTo("EE");
        assertThat(authenticationResult.getSubject()).isEqualTo("EE38001085718");
        assertThat(authenticationResult.getDateOfBirth()).isEqualTo(LocalDate.of(1980, 1, 8));
        assertThat(authenticationResult.getAcr()).isEqualTo(LevelOfAssurance.HIGH);
        assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp.test");
        assertThat(authenticationResult.getErrorCode()).isNull();
        verify(statisticsLogger).logExternalTransaction(same(taraSession), any(OcspInfo.class));
        verify(ocspRequestResponseLogger).logSuccess("http://ocsp.test", null, ocspResp);
    }

    @Test
    void processOcspValidationResults_whenOcspRequestFailed_setsTranslatedErrorCodeAndLogsStatisticsWithException() throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        when(taraSession.getAuthenticationResult()).thenReturn(authenticationResult);
        UserCertificateRevokedException ocspError = new UserCertificateRevokedException();
        ValidationInfo validationInfo = new ValidationInfo(loadCertificate(), List.of(
                new RevocationInfo(URI.create("http://ocsp.test"), Map.of(RevocationInfo.KEY_OCSP_ERROR, ocspError))));

        service.processOcspValidationResults(validationInfo, taraSession);

        assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_REVOKED);
        assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp.test");
        verify(statisticsLogger).logExternalTransaction(same(taraSession), same(ocspError), any(OcspInfo.class));
        verify(ocspRequestResponseLogger).logFailure("http://ocsp.test", null, null, ocspError);
    }

    @Test
    void updateAuthenticationResult_whenEmailScopeRequested_setsEmailFromCertificate() throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        when(taraSession.getAuthenticationResult()).thenReturn(authenticationResult);
        when(taraSession.isEmailScopeRequested()).thenReturn(true);

        service.updateAuthenticationResult(taraSession, loadCertificate(), "http://ocsp.test");

        assertThat(authenticationResult.getEmail()).isEqualTo("38001085718@eesti.ee");
        assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp.test");
    }

    private LoginTestData givenSuccessfulLoginValidation(AuthTokenValidator validator) throws Exception {
        TaraSession taraSession = mock(TaraSession.class);
        TaraSession.Client client = mock(TaraSession.Client.class);
        TaraSession.IdCardAuthenticationResult authenticationResult = mock(TaraSession.IdCardAuthenticationResult.class);
        WebEidAuthToken authToken = mock(WebEidAuthToken.class);
        ValidationInfo validationInfo = mock(ValidationInfo.class);
        X509Certificate certificate = loadCertificate();
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
        return new LoginTestData(taraSession, client, data);
    }

    private record LoginTestData(
            TaraSession taraSession,
            TaraSession.Client client,
            IdCardLoginController.WebEidData data
    ) {
    }

    private static X509Certificate loadCertificate() throws Exception {
        try (InputStream inputStream = Files.newInputStream(Path.of("src/test/resources/id-card/38001085718(TEST_of_ESTEID2018).pem"))) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }
}
