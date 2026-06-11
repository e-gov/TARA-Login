package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.TestUtils;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.exceptions.ChallengeNonceExpiredException;
import eu.webeid.security.exceptions.ChallengeNonceNotFoundException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_FORBIDDEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.MockitoUtil.ANSWER_THROW_EXCEPTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class IdCardLoginServiceTest {

    private static final String CERTIFICATE_POLICY_OID = "1.3.6.1.4.1.51361.1.2.1";
    private static final String EIDAS_CLIENT_ID = "eidas-client";
    private static final String NONCE = "nonce";
    public static final String VALID_CERT_PATH = "id-card/38001085718(TEST_of_ESTEID2018).pem";

    private AuthTokenValidator authTokenValidator;
    private ChallengeNonceStore nonceStore;
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;
    private AuthConfigurationProperties.Ocsp ocsp;
    private AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private AuthTokenValidatorResolver authTokenValidatorResolver;
    private StatisticsLogger statisticsLogger;
    private MockHttpServletRequest request;

    private IdCardLoginService service;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        authTokenValidator = mock(AuthTokenValidator.class, ANSWER_THROW_EXCEPTION);
        nonceStore = mock(ChallengeNonceStore.class, ANSWER_THROW_EXCEPTION);
        authTokenValidatorResolver = mock(AuthTokenValidatorResolver.class, ANSWER_THROW_EXCEPTION);
        statisticsLogger = mock(StatisticsLogger.class);

        ocsp = new AuthConfigurationProperties.Ocsp();
        ocsp.setEnabled(false);
        configurationProperties = new AuthConfigurationProperties.IdCardAuthConfigurationProperties();
        configurationProperties.setOcsp(ocsp);
        configurationProperties.setLevelOfAssurance(LevelOfAssurance.HIGH);
        filterForEidasProxy = spy(new AuthConfigurationProperties.FilterForEidasProxy());
        filterForEidasProxy.setClientId(EIDAS_CLIENT_ID);

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

    @Nested
    class AttemptLogin {

        @Test
        void attemptLogin_whenValidationSucceeds_passesNonceAndAuthTokenToResolvedValidator() throws Exception {
            LoginTestData loginTestData = givenLoginRequest();
            givenValidationSucceeds(loginTestData, List.of());

            service.attemptLogin(loginTestData.data(), loginTestData.taraSession());

            verify(authTokenValidatorResolver).resolve(loginTestData.taraSession().getOriginalClient());
            verify(authTokenValidator).validate(same(loginTestData.authToken()), eq(NONCE));
        }

        @Test
        void attemptLogin_whenValidationSucceeds_completesAuthenticationAndStoresSessionInHttpSession() throws Exception {
            LoginTestData login = givenLoginRequest();
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        }

        @Test
        void attemptLogin_whenOcspDisabled_updatesAuthenticationResultWithoutOcspUrl() throws Exception {
            ocsp.setEnabled(false);
            LoginTestData login = givenLoginRequest();
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            assertThat(login.authenticationResult().getIdCode()).isEqualTo("38001085718");
            assertThat(login.authenticationResult().getOcspUrl()).isNull();
            assertThat(login.authenticationResult().getErrorCode()).isNull();
        }

        @ParameterizedTest
        @MethodSource("nonceRetrievalFailures")
        void attemptLogin_whenNonceMissingOrExpired_throwsBadRequestWithInvalidRequestAndLeavesSessionUntouched(AuthTokenException exception) throws Exception {
            doThrow(exception).when(nonceStore).getAndRemove();
            TaraSession taraSession = buildTaraSession(new TaraSession.IdCardAuthenticationResult());
            IdCardLoginController.WebEidData data = new IdCardLoginController.WebEidData();

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(data, taraSession))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(INVALID_REQUEST));

            assertThat(taraSession.getState()).isEqualTo(INIT_AUTH_PROCESS);
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isNull();
            verifyNoInteractions(authTokenValidatorResolver);
        }

        static Stream<AuthTokenException> nonceRetrievalFailures() {
            return Stream.of(new ChallengeNonceNotFoundException(), new ChallengeNonceExpiredException());
        }

        @Test
        void attemptLogin_whenCertificateExpired_throwsBadRequestWithCertificateExpiredExceptionCause() throws Exception {
            LoginTestData login = givenLoginRequest();
            CertificateExpiredException exception = new CertificateExpiredException("User certificate has expired", null);
            doThrow(exception).when(authTokenValidator).validate(any(), any());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_CERT_EXPIRED));

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

        @Test
        void attemptLogin_whenCertificateNotYetValid_throwsBadRequestWithCertNotYetValid() throws Exception {
            LoginTestData login = givenLoginRequest();
            CertificateNotYetValidException exception = new CertificateNotYetValidException("User certificate is not yet valid", null);
            doThrow(exception).when(authTokenValidator).validate(any(), any());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_CERT_NOT_YET_VALID));

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

        @Test
        void attemptLogin_whenValidationFailsWithGenericAuthTokenException_throwsBadRequestWithValidationErrorResultOther() throws Exception {
            LoginTestData login = givenLoginRequest();
            AuthTokenParseException exception = new AuthTokenParseException("Auth token is null or empty");
            doThrow(exception).when(authTokenValidator).validate(any(), any());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_VALIDATION_ERROR_RESULT_OTHER));

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

        @Test
        void attemptLogin_whenEidasClientWithAllowedPolicyOid_completesAuthentication() throws Exception {
            LoginTestData login = givenLoginRequest();
            login.taraSession().getOriginalClient().setClientId(EIDAS_CLIENT_ID);
            filterForEidasProxy.setAllowedPolicyOids(Set.of(CERTIFICATE_POLICY_OID));
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        }

        @Test
        void attemptLogin_whenEidasClientWithoutAllowedPolicyOid_throwsBadRequestWithCertForbidden() throws Exception {
            LoginTestData login = givenLoginRequest();
            login.taraSession().getOriginalClient().setClientId(EIDAS_CLIENT_ID);
            filterForEidasProxy.setAllowedPolicyOids(Set.of("1.2.3.4"));
            givenValidationSucceeds(login, List.of());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withMessage("eIDAS authentication with given certificate policy OID is forbidden")
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_CERT_FORBIDDEN));

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

        @Test
        void attemptLogin_whenNotEidasClient_skipsCertificatePolicyValidation() throws Exception {
            LoginTestData login = givenLoginRequest();
            // Would fail with IDC_CERT_FORBIDDEN if the policy OID filter were applied to this client.
            filterForEidasProxy.setAllowedPolicyOids(Set.of("1.2.3.4"));
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            verify(filterForEidasProxy, never()).getAllowedPolicyOids();
            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        }

        @Test
        void attemptLogin_whenEidasProxyClientIdNotConfigured_skipsCertificatePolicyValidation() throws Exception {
            LoginTestData login = givenLoginRequest();
            // An unconfigured filter client ID must not match any client nor cause a NullPointerException.
            filterForEidasProxy.setClientId(null);
            filterForEidasProxy.setAllowedPolicyOids(Set.of("1.2.3.4"));
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            verify(filterForEidasProxy, never()).getAllowedPolicyOids();
            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        }

        @Test
        void attemptLogin_whenValidationSucceeds_storesCertificatePolicyOidsForStatisticsLogging() throws Exception {
            LoginTestData login = givenLoginRequest();
            givenValidationSucceeds(login, List.of());

            service.attemptLogin(login.data(), login.taraSession());

            assertThat(login.authenticationResult().getCertificatePolicyOids())
                    .containsExactly(CERTIFICATE_POLICY_OID, "0.4.0.2042.1.2");
        }

        @Test
        void attemptLogin_whenEidasClientAndCertificateWithoutPolicies_throwsBadRequestWithCertForbidden() throws Exception {
            LoginTestData login = givenLoginRequest();
            login.taraSession().getOriginalClient().setClientId(EIDAS_CLIENT_ID);
            filterForEidasProxy.setAllowedPolicyOids(Set.of(CERTIFICATE_POLICY_OID));
            ValidationInfo validationInfo = new ValidationInfo(generateCertificateWithoutPolicies(), List.of());
            doReturn(validationInfo).when(authTokenValidator).validate(same(login.authToken()), eq(NONCE));

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_CERT_FORBIDDEN));

            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

    }

    private LoginTestData givenLoginRequest() throws Exception {
        TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
        TaraSession taraSession = buildTaraSession(authenticationResult);
        WebEidAuthToken authToken = mock(WebEidAuthToken.class);
        IdCardLoginController.WebEidData data = new IdCardLoginController.WebEidData();
        data.setAuthToken(authToken);

        doReturn(new ChallengeNonce(NONCE, ZonedDateTime.now().plusMinutes(5))).when(nonceStore).getAndRemove();
        doReturn(authTokenValidator).when(authTokenValidatorResolver).resolve(taraSession.getOriginalClient());
        return new LoginTestData(taraSession, data, authToken, authenticationResult);
    }

    private void givenValidationSucceeds(LoginTestData login, List<RevocationInfo> revocationInfoList) throws Exception {
        ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), revocationInfoList);
        doReturn(validationInfo).when(authTokenValidator).validate(same(login.authToken()), eq(NONCE));
    }

    private void assertSessionStoredWithState(LoginTestData login, TaraAuthenticationState state) {
        assertThat(login.taraSession().getState()).isEqualTo(state);
        assertThat(request.getSession().getAttribute(TARA_SESSION)).isSameAs(login.taraSession());
    }

    private TaraSession buildTaraSession(TaraSession.IdCardAuthenticationResult authenticationResult) {
        return MockTaraSessionBuilder.builder()
                .sessionId(request.getSession().getId())
                .authenticationResult(authenticationResult)
                .build();
    }

    private record LoginTestData(
            TaraSession taraSession,
            IdCardLoginController.WebEidData data,
            WebEidAuthToken authToken,
            TaraSession.IdCardAuthenticationResult authenticationResult
    ) {
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
