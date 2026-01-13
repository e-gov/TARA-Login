package ee.ria.taraauthserver.authentication.smartid.web2app;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.authentication.smartid.RpChallengeService;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.SidAuthenticationResult;
import ee.ria.taraauthserver.session.update.FailSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.PollSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import ee.ria.taraauthserver.utils.LanguageUtil;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.DeviceLinkAuthenticationSessionRequestBuilder;
import ee.sk.smartid.DeviceLinkType;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SessionType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.common.devicelink.CallbackUrl;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.CallbackUrlUtil;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.ProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static co.elastic.apm.api.Outcome.FAILURE;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.SID_DOCUMENT_UNUSABLE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_INTERACTION_NOT_SUPPORTED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_INTERNAL_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.SID_REQUEST_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SID_SESSION_TIMEOUT;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_ACCOUNT_NOT_FOUND;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE;
import static ee.ria.taraauthserver.error.ErrorCode.SID_USER_REFUSED_DISAPLAYTEXTANDPIN;
import static ee.ria.taraauthserver.error.ErrorCode.SID_VALIDATION_ERROR;
import static ee.ria.taraauthserver.error.ErrorCode.SID_WRONG_VC;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdc;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.MILLIS;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@Service
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.web2app.enabled"
        },
        havingValue = "true"
)
public class AuthSidWeb2AppService {

    private static final Map<Class<?>, ErrorCode> errorMap;
    private static final String RELATIVE_CALLBACK_URL = "auth/sid/web2app/callback";

    static {
        errorMap = new HashMap<>();
        errorMap.put(InternalServerErrorException.class, SID_INTERNAL_ERROR);
        errorMap.put(ProcessingException.class, SID_REQUEST_TIMEOUT);
        errorMap.put(UserRefusedException.class, SID_USER_REFUSED);
        errorMap.put(SessionTimeoutException.class, SID_SESSION_TIMEOUT);
        errorMap.put(DocumentUnusableException.class, SID_DOCUMENT_UNUSABLE);
        errorMap.put(UserSelectedWrongVerificationCodeException.class, SID_WRONG_VC);
        errorMap.put(RequiredInteractionNotSupportedByAppException.class, SID_INTERACTION_NOT_SUPPORTED);
        errorMap.put(UserRefusedDisplayTextAndPinException.class, SID_USER_REFUSED_DISAPLAYTEXTANDPIN);
        errorMap.put(UserAccountNotFoundException.class, SID_USER_ACCOUNT_NOT_FOUND);
        errorMap.put(UserRefusedConfirmationMessageException.class, SID_USER_REFUSED_CONFIRMATIONMESSAGE);
        errorMap.put(UserRefusedConfirmationMessageWithVerificationChoiceException.class, SID_USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE);
        errorMap.put(ServiceNotAvailableException.class, SID_INTERNAL_ERROR);
        errorMap.put(UnprocessableSmartIdResponseException.class, SID_VALIDATION_ERROR);
        errorMap.put(CertificateLevelMismatchException.class, SID_VALIDATION_ERROR);
    }

    @Autowired
    private SmartIdClient sidClient;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private DeviceLinkAuthenticationResponseValidator responseValidator;

    @Autowired
    private SmartIdConfigurationProperties smartIdConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private Executor applicationTaskExecutor;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @Autowired
    private RpChallengeService rpChallengeService;

    public URI startSidAuthSession(TaraSession taraSession) throws URISyntaxException {
        RpChallenge rpChallenge = rpChallengeService.getRpChallenge();
        taraSession.accept(new InitSmartIdWeb2AppAuthenticationSessionUpdate());
        updateSession(taraSession);

        RelyingParty relyingParty = taraSession.getSmartIdRelyingParty()
                .orElse(smartIdConfigurationProperties.getRelyingParty());
        String shortName = defaultIfNull(
                taraSession.getOriginalClient().getTranslatedShortName(),
                smartIdConfigurationProperties.getDisplayText());
        String callbackUrl = authConfigurationProperties.getSiteOrigin()
                .toURI()
                .resolve(RELATIVE_CALLBACK_URL)
                .toString();
        CallbackUrl callbackUrlWithToken = CallbackUrlUtil.createCallbackUrl(callbackUrl);
        DeviceLinkAuthenticationSessionRequestBuilder requestBuilder = sidClient
                .createDeviceLinkAuthentication()
                .withInitialCallbackUrl(callbackUrlWithToken.initialCallbackUri().toString())
                .withRpChallenge(rpChallenge.toBase64EncodedValue())
                .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPin(shortName)))
                .withRelyingPartyUUID(relyingParty.getUuid())
                .withRelyingPartyName(relyingParty.getName())
                .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);

        DeviceLinkSessionResponse sessionResponse = initAuthentication(taraSession, requestBuilder);
        DeviceLinkAuthenticationSessionRequest sessionRequest = requestBuilder.getAuthenticationSessionRequest();
        String language = LanguageUtil.toIso3(taraSession.getChosenLanguage());
        return createDeviceLink(
                sessionRequest.interactions(),
                sessionResponse,
                language,
                rpChallenge,
                callbackUrlWithToken.initialCallbackUri().toString());
    }

    private URI createDeviceLink(
            String interactions,
            DeviceLinkSessionResponse sessionResponse,
            String language,
            RpChallenge rpChallenge,
            String callbackUrl) {
        return sidClient.createDynamicContent()
                .withDeviceLinkBase(sessionResponse.deviceLinkBase().toString())
                .withDeviceLinkType(DeviceLinkType.WEB_2_APP)
                .withInitialCallbackUrl(callbackUrl)
                .withSessionToken(sessionResponse.sessionToken())
                .withSessionType(SessionType.AUTHENTICATION)
                .withLang(language)
                .withDigest(rpChallenge.toBase64EncodedValue())
                .withInteractions(interactions)
                .withSchemeName(smartIdConfigurationProperties.getSchemaName())
                .buildDeviceLink(sessionResponse.sessionSecret());
    }

    private DeviceLinkSessionResponse initAuthentication(
            TaraSession taraSession,
            DeviceLinkAuthenticationSessionRequestBuilder requestBuilder) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(now().plus(200, MILLIS).toEpochMilli() * 1_000);
        try (final Scope ignored = span.activate()) {
            DeviceLinkSessionResponse authenticationSessionResponse = requestBuilder.initAuthenticationSession();
            String sidSessionId = authenticationSessionResponse.sessionID();
            log.info("Initiated Smart-ID Web2App session with id: {}",
                    value("tara.session.authentication_result.sid_session_id", sidSessionId));
            taraSession.accept(new PollSmartIdWeb2AppAuthenticationSessionUpdate(
                    sidSessionId,
                    requestBuilder.getAuthenticationSessionRequest()
            ));
            createAuthenticationResult(taraSession, sidSessionId);
            return authenticationSessionResponse;
        } catch (Exception e) {
            createAuthenticationResult(taraSession, null);
            handleSidAuthenticationException(taraSession, e);
            handleStatisticsLogging(taraSession, e);
            throw e;
        } finally {
            updateSession(taraSession);
            span.end();
        }
    }

    private static void createAuthenticationResult(TaraSession taraSession, String sidSessionId) {
        SidAuthenticationResult sidAuthenticationResult = new SidAuthenticationResult(sidSessionId);
        sidAuthenticationResult.setAmr(AuthenticationType.SMART_ID);
        taraSession.setAuthenticationResult(sidAuthenticationResult);
    }

    private void updateSession(TaraSession taraSession) {
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session != null) {
            session.setAttribute(TARA_SESSION, taraSession);
            sessionRepository.save(session);
        } else {
            log.error("Session correlated with this Smart-ID polling process was not found: {}", taraSession.getSessionId());
        }
    }

    public void startPollingAuthenticationResult(TaraSession taraSession, String userChallengeVerifier) {
        CompletableFuture.supplyAsync(
                withMdc(() -> {
                    pollUntilFinalAuthenticationResult(taraSession, userChallengeVerifier);
                    return null; // This is only needed to support the existing signature of withMdc() method
                }),
                applicationTaskExecutor
        );
    }

    private void pollUntilFinalAuthenticationResult(TaraSession taraSession, String userChallengeVerifier) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll");
        span.setName(ElasticApmUtil.currentMethodName());
        span.setStartTimestamp(
                now()
                .plus(200, MILLIS)
                .minus(smartIdConfigurationProperties.getDelayStatusPollingStartInMilliseconds(), MILLIS)
                .toEpochMilli() * 1_000);
        try (final Scope scope = span.activate()) {
            SessionStatusPoller sessionStatusPoller = sidClient.getSessionStatusPoller();
            log.info("Starting Smart-ID session status polling with id: {}",
                    value("tara.session.sid_authentication_result.sid_session_id", taraSession.getSmartIdWeb2AppSession().getSessionId()));
            SessionStatus sessionStatus = sessionStatusPoller.fetchFinalSessionStatus(taraSession.getSmartIdWeb2AppSession().getSessionId());
            handleSidAuthenticationResult(taraSession, sessionStatus, userChallengeVerifier);
            taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
            statisticsLogger.logExternalTransaction(taraSession);
        } catch (Exception ex) {
            handleSidAuthenticationException(taraSession, ex);
            handleStatisticsLogging(taraSession, ex);
        } finally {
            updateSession(taraSession);
            span.end();
        }
    }

    private void handleSidAuthenticationResult(
            TaraSession taraSession,
            SessionStatus sessionStatus,
            String userChallengeVerifier) {
        SidAuthenticationResult taraAuthResult = (SidAuthenticationResult) taraSession.getAuthenticationResult();
        String sidSessionId = taraAuthResult.getSidSessionId();
        log.info("SID session id {} authentication result: {}, document number: {}, status: {}",
                value("tara.session.authentication_result.sid_session_id", sidSessionId),
                value("tara.session.authentication_result.sid_end_result", sessionStatus.getResult().getEndResult()),
                value("tara.session.authentication_result.sid_document_number", sessionStatus.getResult().getDocumentNumber()),
                value("tara.session.authentication_result.sid_state", sessionStatus.getState()));

        AuthenticationIdentity authIdentity = responseValidator.validate(
                sessionStatus,
                taraSession.getSmartIdWeb2AppSession().getAuthenticationSessionRequest(),
                userChallengeVerifier,
                smartIdConfigurationProperties.getSchemaName());
        // TODO: SidAuthenticationResult fields were previously populated *before* calling responseValidator.validate(),
        //  so that this information would be available in case of validation failure and could be logged with full details.
        //  Since Smart ID v3, this is no longer possible, but the impact of missing information is not known yet.
        //  We need to populate as many taraAuthResult fields as possible before validation. This information needs
        //  to be taken from somewhere else now.
        taraAuthResult.setIdCode(authIdentity.getIdentityNumber());
        taraAuthResult.setCountry(authIdentity.getCountry());
        taraAuthResult.setFirstName(authIdentity.getGivenName());
        taraAuthResult.setLastName(authIdentity.getSurname());
        taraAuthResult.setSubject(authIdentity.getCountry() + authIdentity.getIdentityNumber());
        taraAuthResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(authIdentity.getIdentityNumber()));
        taraAuthResult.setAmr(AuthenticationType.SMART_ID);
        taraAuthResult.setAcr(smartIdConfigurationProperties.getLevelOfAssurance());
    }

    private void handleSidAuthenticationException(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = translateExceptionToErrorCode(ex);
        taraSession.accept(new FailSmartIdWeb2AppAuthenticationSessionUpdate(errorCode));

        if (ERROR_GENERAL == errorCode || SID_INTERNAL_ERROR == errorCode || SID_VALIDATION_ERROR == errorCode) {
            log.error(append("error.code", errorCode.name()), "Smart-ID authentication exception: {}", ex.getMessage(), ex);
        } else {
            log.warn("Smart-ID authentication failed: {}, Error code: {}", value("error.message", ex.getMessage()), value("error.code", errorCode.name()));
        }

        updateSession(taraSession);

        Span span = ElasticApm.currentSpan();
        span.setOutcome(FAILURE);
        span.captureException(ex);
    }

    private void handleStatisticsLogging(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = taraSession.getAuthenticationResult().getErrorCode();
        if (ERROR_GENERAL == errorCode || SID_INTERNAL_ERROR == errorCode || SID_VALIDATION_ERROR == errorCode) {
            statisticsLogger.logExternalTransaction(taraSession, ex);
        } else {
            statisticsLogger.logExternalTransaction(taraSession);
        }
    }

    private ErrorCode translateExceptionToErrorCode(Throwable ex) {
        return errorMap.getOrDefault(ex.getClass(), ERROR_GENERAL);
    }

}
