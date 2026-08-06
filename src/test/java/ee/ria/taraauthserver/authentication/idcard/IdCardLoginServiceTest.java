package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

    private IdCardLoginService service;

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        authTokenValidator = mock(AuthTokenValidator.class);
        nonceStore = mock(ChallengeNonceStore.class);
        StatisticsLogger statisticsLogger = mock(StatisticsLogger.class);
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
