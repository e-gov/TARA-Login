package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.TaraScope;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.TestUtils;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
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
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_FORBIDDEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.MockitoUtil.ANSWER_THROW_EXCEPTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    private OcspRequestResponseLogger ocspRequestResponseLogger;
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
        ocspRequestResponseLogger = mock(OcspRequestResponseLogger.class);

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
                authTokenValidatorResolver,
                ocspRequestResponseLogger
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

        @Test
        void attemptLogin_whenOcspEnabled_keepsAuthenticationResultFromOcspValidation() throws Exception {
            ocsp.setEnabled(true);
            LoginTestData login = givenLoginRequest();
            OCSPResp ocspResp = mock(OCSPResp.class);
            givenValidationSucceeds(login, List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

            service.attemptLogin(login.data(), login.taraSession());

            assertThat(login.authenticationResult().getIdCode()).isEqualTo("38001085718");
            assertThat(login.authenticationResult().getOcspUrl()).isEqualTo("http://ocsp.test");
            verify(ocspRequestResponseLogger).logSuccess("http://ocsp.test", null, ocspResp);
            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
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
        void attemptLogin_whenCertificateRevoked_processesOcspResultsBeforeThrowingBadRequest() throws Exception {
            LoginTestData login = givenLoginRequest();
            OCSPResp ocspResp = mock(OCSPResp.class);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));
            ResilientUserCertificateRevokedException exception = new ResilientUserCertificateRevokedException(validationInfo);
            doThrow(exception).when(authTokenValidator).validate(any(), any());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_REVOKED));

            assertThat(login.authenticationResult().getOcspUrl()).isEqualTo("http://ocsp.test");
            ArgumentCaptor<OcspInfo> ocspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(login.taraSession()), ocspInfo.capture());
            assertThat(ocspInfo.getValue().ocspResp()).isSameAs(ocspResp);
            verify(ocspRequestResponseLogger).logSuccess("http://ocsp.test", null, ocspResp);
            assertSessionStoredWithState(login, NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        }

        @Test
        void attemptLogin_whenOcspCheckFailedWithRevokedStatus_processesOcspResultsAndThrowsBadRequestWithValidationErrorResultRevoked() throws Exception {
            LoginTestData login = givenLoginRequest();
            OCSPResp ocspResp = ocspRespWithCertificateStatus(new RevokedStatus(new Date(), 0));
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));
            ResilientUserCertificateOCSPCheckFailedException exception
                    = new ResilientUserCertificateOCSPCheckFailedException("User certificate OCSP check failed", validationInfo);
            doThrow(exception).when(authTokenValidator).validate(any(), any());

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> service.attemptLogin(login.data(), login.taraSession()))
                    .withCause(exception)
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(IDC_VALIDATION_ERROR_RESULT_REVOKED));

            assertThat(login.authenticationResult().getOcspUrl()).isEqualTo("http://ocsp.test");
            ArgumentCaptor<OcspInfo> ocspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(login.taraSession()), ocspInfo.capture());
            assertThat(ocspInfo.getValue().ocspResp()).isSameAs(ocspResp);
            verify(ocspRequestResponseLogger).logSuccess("http://ocsp.test", null, ocspResp);
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

    }

    @Nested
    class ProcessOcspValidationResults {

        @Test
        void processOcspValidationResults_whenRevocationInfoListEmpty_updatesNothingAndLogsNothing() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of());

            service.processOcspValidationResults(validationInfo, taraSession);

            assertThat(authenticationResult.getIdCode()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isNull();
            assertThat(authenticationResult.getErrorCode()).isNull();
            verifyNoInteractions(statisticsLogger, ocspRequestResponseLogger);
        }

        @Test
        void processOcspValidationResults_whenOcspResponseAttributesParsingFails_throwsAndUpdatesNothingAndLogsNothing() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH),
                    Collections.singletonList(null));

            assertThatThrownBy(() -> service.processOcspValidationResults(validationInfo, taraSession))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Revocation info cannot be null");

            assertThat(authenticationResult.getIdCode()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isNull();
            assertThat(authenticationResult.getErrorCode()).isNull();
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isNull();
            verifyNoInteractions(statisticsLogger, ocspRequestResponseLogger);
        }

        @Test
        void processOcspValidationResults_whenSuccessfulResponseNotLast_throwsIllegalStateException() {
            TaraSession taraSession = buildTaraSession(new TaraSession.IdCardAuthenticationResult());
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp1.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, mock(OCSPResp.class))),
                    new RevocationInfo(URI.create("http://ocsp2.test"), Map.of())));

            assertThatThrownBy(() -> service.processOcspValidationResults(validationInfo, taraSession))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Only the last response can be successful");

            verifyNoInteractions(statisticsLogger, ocspRequestResponseLogger);
        }

        @Test
        void processOcspValidationResults_whenLastResponseSuccessful_updatesAuthenticationResultAndLogsSuccessfulOcspResponse() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            OCSPReq ocspReq = mock(OCSPReq.class);
            OCSPResp ocspResp = mock(OCSPResp.class);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), Map.of(
                            RevocationInfo.KEY_OCSP_REQUEST, ocspReq,
                            RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

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
            ArgumentCaptor<OcspInfo> ocspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(taraSession), ocspInfo.capture());
            assertThat(ocspInfo.getValue().ocspResp()).isSameAs(ocspResp);
            assertThat(ocspInfo.getValue().requestCount()).isEqualTo(1);
            assertThat(ocspInfo.getValue().isLastRequest()).isTrue();
            verify(ocspRequestResponseLogger).logSuccess("http://ocsp.test", ocspReq, ocspResp);
        }

        @Test
        void processOcspValidationResults_whenOcspRequestFailed_updatesAuthenticationResultWithTranslatedErrorAndLogsFailedOcspResponse() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            UserCertificateRevokedException ocspError = new UserCertificateRevokedException();
            OCSPReq ocspReq = mock(OCSPReq.class);
            OCSPResp ocspResp = mock(OCSPResp.class);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), Map.of(
                            RevocationInfo.KEY_OCSP_REQUEST, ocspReq,
                            RevocationInfo.KEY_OCSP_RESPONSE, ocspResp,
                            RevocationInfo.KEY_OCSP_ERROR, ocspError))));

            service.processOcspValidationResults(validationInfo, taraSession);

            assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_REVOKED);
            assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp.test");
            ArgumentCaptor<OcspInfo> ocspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(taraSession), same(ocspError), ocspInfo.capture());
            assertThat(ocspInfo.getValue().requestCount()).isEqualTo(1);
            assertThat(ocspInfo.getValue().isLastRequest()).isTrue();
            assertThat(ocspInfo.getValue().ocspResp()).isSameAs(ocspResp);
            verify(ocspRequestResponseLogger).logFailure("http://ocsp.test", ocspReq, ocspResp, ocspError);
        }

        @Test
        void processOcspValidationResults_whenMultipleFailedResponses_keepsErrorCodeOfLastFailure() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            UserCertificateRevokedException firstError = new UserCertificateRevokedException();
            OCSPClientException lastError = new OCSPClientException("OCSP request failed", null, 503);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp1.test"), Map.of(RevocationInfo.KEY_OCSP_ERROR, firstError)),
                    new RevocationInfo(URI.create("http://ocsp2.test"), Map.of(RevocationInfo.KEY_OCSP_ERROR, lastError))));

            service.processOcspValidationResults(validationInfo, taraSession);

            assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_OCSP_NOT_AVAILABLE);
            assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp2.test");
            verify(ocspRequestResponseLogger).logFailure("http://ocsp1.test", null, null, firstError);
            verify(ocspRequestResponseLogger).logFailure("http://ocsp2.test", null, null, lastError);
            verify(statisticsLogger).logExternalTransaction(same(taraSession), same(firstError), any(OcspInfo.class));
            verify(statisticsLogger).logExternalTransaction(same(taraSession), same(lastError), any(OcspInfo.class));
        }

        @Test
        void processOcspValidationResults_whenFailedResponseFollowedBySuccess_clearsErrorCodeAndLogsBothResponses() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);
            UserCertificateRevokedException ocspError = new UserCertificateRevokedException();
            OCSPResp ocspResp = mock(OCSPResp.class);
            ValidationInfo validationInfo = new ValidationInfo(TestUtils.loadCertificateFromResource(VALID_CERT_PATH), List.of(
                    new RevocationInfo(URI.create("http://ocsp1.test"), Map.of(RevocationInfo.KEY_OCSP_ERROR, ocspError)),
                    new RevocationInfo(URI.create("http://ocsp2.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

            service.processOcspValidationResults(validationInfo, taraSession);

            assertThat(authenticationResult.getErrorCode()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp2.test");
            verify(ocspRequestResponseLogger).logFailure("http://ocsp1.test", null, null, ocspError);
            verify(ocspRequestResponseLogger).logSuccess("http://ocsp2.test", null, ocspResp);
            ArgumentCaptor<OcspInfo> failedOcspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(taraSession), same(ocspError), failedOcspInfo.capture());
            assertThat(failedOcspInfo.getValue().requestCount()).isEqualTo(1);
            assertThat(failedOcspInfo.getValue().isLastRequest()).isFalse();
            ArgumentCaptor<OcspInfo> successfulOcspInfo = ArgumentCaptor.forClass(OcspInfo.class);
            verify(statisticsLogger).logExternalTransaction(same(taraSession), successfulOcspInfo.capture());
            assertThat(successfulOcspInfo.getValue().requestCount()).isEqualTo(2);
            assertThat(successfulOcspInfo.getValue().isLastRequest()).isTrue();
        }

        @ParameterizedTest
        @MethodSource("successfulAndFailedRevocationInfoAttributes")
        void processOcspValidationResults_whenUpdatingAuthenticationResultFails_throwsAndLogsNothing(Map<String, Object> revocationInfoAttributes) {
            TaraSession taraSession = buildTaraSession(new TaraSession.IdCardAuthenticationResult());
            ValidationInfo validationInfo = new ValidationInfo(givenCertificateWithInvalidEstonianIdCode(), List.of(
                    new RevocationInfo(URI.create("http://ocsp.test"), revocationInfoAttributes)));

            assertThatThrownBy(() -> service.processOcspValidationResults(validationInfo, taraSession))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid Estonian identity code");

            verifyNoInteractions(statisticsLogger, ocspRequestResponseLogger);
        }

        static Stream<Named<Map<String, Object>>> successfulAndFailedRevocationInfoAttributes() {
            return Stream.of(
                    Named.of("successful OCSP response", Map.of(RevocationInfo.KEY_OCSP_RESPONSE, mock(OCSPResp.class))),
                    Named.of("failed OCSP response", Map.of(RevocationInfo.KEY_OCSP_ERROR, new UserCertificateRevokedException())));
        }

        private X509Certificate givenCertificateWithInvalidEstonianIdCode() {
            X509Certificate certificate = mock(X509Certificate.class);
            doReturn(BigInteger.ONE).when(certificate).getSerialNumber();
            doReturn(new X500Principal("CN=Test")).when(certificate).getSubjectX500Principal();
            doReturn(new X500Principal("CN=Test CA")).when(certificate).getIssuerX500Principal();
            Principal subjectDN = mock(Principal.class);
            doReturn(subjectDN).when(certificate).getSubjectDN();
            doReturn("SERIALNUMBER=99999999999, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=Test, C=EE")
                    .when(subjectDN).getName();
            return certificate;
        }
    }

    @Nested
    class UpdateAuthenticationResult {

        @Test
        void updateAuthenticationResult_whenEmailScopeRequested_setsEmailFromCertificate() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = MockTaraSessionBuilder.builder()
                    .sessionId(request.getSession().getId())
                    .requestedScopes(List.of(TaraScope.EMAIL.getFormalName()))
                    .authenticationResult(authenticationResult)
                    .build();

            service.updateAuthenticationResult(taraSession, TestUtils.loadCertificateFromResource(VALID_CERT_PATH), "http://ocsp.test");

            assertThat(authenticationResult.getEmail()).isEqualTo("38001085718@eesti.ee");
        }

        @Test
        void updateAuthenticationResult_whenEmailScopeNotRequested_leavesEmailNull() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            TaraSession taraSession = buildTaraSession(authenticationResult);

            service.updateAuthenticationResult(taraSession, TestUtils.loadCertificateFromResource(VALID_CERT_PATH), "http://ocsp.test");

            assertThat(authenticationResult.getEmail()).isNull();
        }

        @Test
        void updateAuthenticationResult_whenErrorCodePreviouslySet_setsValuesClearsErrorCodeAndStoresSessionInHttpSession() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            authenticationResult.setErrorCode(IDC_REVOKED);
            TaraSession taraSession = buildTaraSession(authenticationResult);

            service.updateAuthenticationResult(taraSession, TestUtils.loadCertificateFromResource(VALID_CERT_PATH), "http://ocsp.test");

            assertThat(authenticationResult.getErrorCode()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isEqualTo("http://ocsp.test");
            assertThat(authenticationResult.getCertificatePolicyOids())
                    .containsExactlyInAnyOrder(CERTIFICATE_POLICY_OID, "0.4.0.2042.1.2");
            assertThat(authenticationResult.getFirstName()).isEqualTo("JAAK-KRISTJAN");
            assertThat(authenticationResult.getLastName()).isEqualTo("JÕEORG");
            assertThat(authenticationResult.getIdCode()).isEqualTo("38001085718");
            assertThat(authenticationResult.getCountry()).isEqualTo("EE");
            assertThat(authenticationResult.getDateOfBirth()).isEqualTo(LocalDate.of(1980, 1, 8));
            assertThat(authenticationResult.getAcr()).isEqualTo(LevelOfAssurance.HIGH);
            assertThat(authenticationResult.getSubject()).isEqualTo("EE38001085718");
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isSameAs(taraSession);
        }

        @Test
        void updateAuthenticationResult_whenCertificateSerialNumberIsNotValidEstonianIdCode_throwsAndLeavesAuthenticationResultAndSessionUntouched() {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            authenticationResult.setErrorCode(IDC_REVOKED);
            TaraSession taraSession = buildTaraSession(authenticationResult);
            X509Certificate certificate = mock(X509Certificate.class);
            Principal subjectDN = mock(Principal.class);
            doReturn(subjectDN).when(certificate).getSubjectDN();
            doReturn("SERIALNUMBER=99999999999, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=Test, C=EE")
                    .when(subjectDN).getName();

            assertThatThrownBy(() -> service.updateAuthenticationResult(taraSession, certificate, "http://ocsp.test"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid Estonian identity code");

            assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_REVOKED);
            assertThat(authenticationResult.getIdCode()).isNull();
            assertThat(authenticationResult.getFirstName()).isNull();
            assertThat(authenticationResult.getLastName()).isNull();
            assertThat(authenticationResult.getSubject()).isNull();
            assertThat(authenticationResult.getDateOfBirth()).isNull();
            assertThat(authenticationResult.getAcr()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isNull();
            assertThat(authenticationResult.getCertificatePolicyOids()).isNull();
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isNull();
        }

        @Test
        void updateAuthenticationResult_whenCertificatePolicyOidsExtractionFails_throwsAndLeavesAuthenticationResultAndSessionUntouched() throws Exception {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            authenticationResult.setErrorCode(IDC_REVOKED);
            TaraSession taraSession = buildTaraSession(authenticationResult);
            X509Certificate certificate = mock(X509Certificate.class);
            Principal subjectDN = mock(Principal.class);
            doReturn(subjectDN).when(certificate).getSubjectDN();
            doReturn("SERIALNUMBER=38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=Test, C=EE")
                    .when(subjectDN).getName();
            CertificateEncodingException encodingException = new CertificateEncodingException("Unable to encode certificate");
            doThrow(encodingException).when(certificate).getEncoded();

            assertThatThrownBy(() -> service.updateAuthenticationResult(taraSession, certificate, "http://ocsp.test"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Failed to extract certificate policy OIDs")
                    .hasCause(encodingException);

            assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_REVOKED);
            assertThat(authenticationResult.getIdCode()).isNull();
            assertThat(authenticationResult.getFirstName()).isNull();
            assertThat(authenticationResult.getLastName()).isNull();
            assertThat(authenticationResult.getSubject()).isNull();
            assertThat(authenticationResult.getDateOfBirth()).isNull();
            assertThat(authenticationResult.getAcr()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isNull();
            assertThat(authenticationResult.getCertificatePolicyOids()).isNull();
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isNull();
        }

        @Test
        void updateAuthenticationResult_whenEmailExtractionFails_throwsAndLeavesAuthenticationResultAndSessionUntouched() throws Exception {
            TaraSession.IdCardAuthenticationResult authenticationResult = new TaraSession.IdCardAuthenticationResult();
            authenticationResult.setErrorCode(IDC_REVOKED);
            TaraSession taraSession = MockTaraSessionBuilder.builder()
                    .sessionId(request.getSession().getId())
                    .requestedScopes(List.of(TaraScope.EMAIL.getFormalName()))
                    .authenticationResult(authenticationResult)
                    .build();
            X509Certificate certificate = mock(X509Certificate.class);
            Principal subjectDN = mock(Principal.class);
            doReturn(subjectDN).when(certificate).getSubjectDN();
            doReturn("SERIALNUMBER=38001085718, GIVENNAME=JAAK-KRISTJAN, SURNAME=JÕEORG, CN=Test, C=EE")
                    .when(subjectDN).getName();
            doReturn(TestUtils.loadCertificateFromResource(VALID_CERT_PATH).getEncoded()).when(certificate).getEncoded();
            doReturn(null).when(certificate).getSubjectAlternativeNames();

            assertThatThrownBy(() -> service.updateAuthenticationResult(taraSession, certificate, "http://ocsp.test"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("This certificate does not contain any Subject Alternative Name fields!");

            assertThat(authenticationResult.getErrorCode()).isEqualTo(IDC_REVOKED);
            assertThat(authenticationResult.getEmail()).isNull();
            assertThat(authenticationResult.getIdCode()).isNull();
            assertThat(authenticationResult.getFirstName()).isNull();
            assertThat(authenticationResult.getLastName()).isNull();
            assertThat(authenticationResult.getSubject()).isNull();
            assertThat(authenticationResult.getDateOfBirth()).isNull();
            assertThat(authenticationResult.getAcr()).isNull();
            assertThat(authenticationResult.getOcspUrl()).isNull();
            assertThat(authenticationResult.getCertificatePolicyOids()).isNull();
            assertThat(request.getSession().getAttribute(TARA_SESSION)).isNull();
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

    private static OCSPResp ocspRespWithCertificateStatus(CertificateStatus certificateStatus) throws Exception {
        OCSPResp ocspResp = mock(OCSPResp.class);
        BasicOCSPResp basicOcspResp = mock(BasicOCSPResp.class);
        SingleResp singleResp = mock(SingleResp.class);
        doReturn(basicOcspResp).when(ocspResp).getResponseObject();
        doReturn(new SingleResp[]{singleResp}).when(basicOcspResp).getResponses();
        doReturn(certificateStatus).when(singleResp).getCertStatus();
        return ocspResp;
    }
}
