package ee.ria.taraauthserver.authentication.smartid.notificationbased;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.authentication.common.AuthenticationDisplayTextBuilder;
import ee.ria.taraauthserver.authentication.smartid.RpChallengeService;
import ee.ria.taraauthserver.authentication.smartid.SmartIdExceptionTranslator;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.SidAuthenticationResult;
import ee.ria.taraauthserver.session.update.AuthenticationFailedSessionUpdate;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.FlowType;
import ee.sk.smartid.NotificationAuthenticationResponseValidator;
import ee.sk.smartid.NotificationAuthenticationSessionRequestBuilder;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.VerificationCodeCalculator;
import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static co.elastic.apm.api.Outcome.FAILURE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdc;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdcAndLocale;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.util.concurrent.CompletableFuture.delayedExecutor;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@Service
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.notification-based.enabled"
        },
        havingValue = "true"
)
public class AuthSidNotificationBasedService {

    @Autowired
    private SmartIdClient sidClient;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private NotificationAuthenticationResponseValidator responseValidator;

    @Autowired
    private SmartIdConfigurationProperties smartIdConfigurationProperties;

    @Autowired
    private Executor applicationTaskExecutor;

    @Autowired
    private StatisticsLogger statisticsLogger;

    @Autowired
    private RpChallengeService rpChallengeService;

    @Autowired
    private AuthenticationDisplayTextBuilder authenticationDisplayTextBuilder;

    public String startSidAuthSession(TaraSession taraSession, String idCode) {
        RpChallenge rpChallenge = rpChallengeService.getRpChallenge();
        String verificationCode = VerificationCodeCalculator.calculate(rpChallenge.value());
        NotificationAuthenticationSessionRequestBuilder requestBuilder = sidClient.createNotificationAuthentication();
        taraSession.setSmartIdFlowType(FlowType.NOTIFICATION);
        taraSession.setState(INIT_SID);
        updateSession(taraSession);

        CompletableFuture
                .supplyAsync(withMdcAndLocale(() -> initAuthentication(idCode, taraSession, rpChallenge, requestBuilder)),
                        delayedExecutor(smartIdConfigurationProperties.getDelayInitiateSidSessionInMilliseconds(), MILLISECONDS, applicationTaskExecutor))
                .thenAcceptAsync(withMdc((authenticationSessionResponse) -> pollAuthenticationResult(authenticationSessionResponse, taraSession, requestBuilder)),
                        delayedExecutor(smartIdConfigurationProperties.getDelayStatusPollingStartInMilliseconds(), MILLISECONDS, applicationTaskExecutor));
        return verificationCode;
    }

    private NotificationAuthenticationSessionResponse initAuthentication(
            String idCode,
            TaraSession taraSession,
            RpChallenge rpChallenge,
            NotificationAuthenticationSessionRequestBuilder requestBuilder) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(
                        now()
                                .plus(200, MILLIS)
                                .minus(smartIdConfigurationProperties.getDelayInitiateSidSession())
                                .toEpochMilli() * 1_000);
        try (final Scope scope = span.activate()) {
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, idCode);
            RelyingParty relyingParty =
                    taraSession.getSmartIdRelyingParty().orElse(smartIdConfigurationProperties.getRelyingParty());
            requestBuilder
                    .withRelyingPartyUUID(relyingParty.getUuid())
                    .withRelyingPartyName(relyingParty.getName())
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
                    .withRpChallenge(rpChallenge.toBase64EncodedValue())
                    .withInteractions(getAppropriateAllowedInteractions(taraSession));

            NotificationAuthenticationSessionResponse authenticationSessionResponse = requestBuilder.initAuthenticationSession();
            String sidSessionId = authenticationSessionResponse.sessionID();
            log.info("Initiated Smart-ID notification based session with id: {}", value("tara.session.authentication_result.sid_session_id", sidSessionId));
            taraSession.setState(POLL_SID_STATUS);
            createAuthenticationResult(taraSession, sidSessionId);
            return authenticationSessionResponse;
        } catch (Exception e) {
            createAuthenticationResult(taraSession, null);
            handleSidAuthenticationException(taraSession, e);
            handleStatisticsLogging(taraSession, e);
        } finally {
            updateSession(taraSession);
            span.end();
        }
        return null;
    }

    private void createAuthenticationResult(TaraSession taraSession, String sidSessionId) {
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

    private List<NotificationInteraction> getAppropriateAllowedInteractions(TaraSession taraSession) {
        List<NotificationInteraction> allowedInteractions = new ArrayList<>();
        String baseShortName = defaultIfNull(
                taraSession.getOriginalClient().getTranslatedShortName(),
                smartIdConfigurationProperties.getDisplayText());
        String shortName = authenticationDisplayTextBuilder.buildLoginDisplayText(baseShortName);
        if (taraSession.isAdditionalSmartIdVerificationCodeCheckNeeded()) {
            allowedInteractions.add(NotificationInteraction.confirmationMessageAndVerificationCodeChoice(shortName));
        }
        allowedInteractions.add(NotificationInteraction.displayTextAndPin(shortName));
        return allowedInteractions;
    }

    private void pollAuthenticationResult(
            NotificationAuthenticationSessionResponse authenticationSessionResponse,
            TaraSession taraSession,
            NotificationAuthenticationSessionRequestBuilder requestBuilder) {
        if (authenticationSessionResponse == null || authenticationSessionResponse.sessionID() == null) {
            return;
        }
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(
                        now()
                                .plus(200, MILLIS)
                                .minus(smartIdConfigurationProperties.getDelayStatusPollingStart())
                                .toEpochMilli() * 1_000);
        try (final Scope scope = span.activate()) {
            SessionStatusPoller sessionStatusPoller = sidClient.getSessionStatusPoller();
            log.info("Starting Smart-ID session status polling with id: {}",
                    value("tara.session.sid_authentication_result.sid_session_id",
                            authenticationSessionResponse.sessionID()));
            SessionStatus sessionStatus = sessionStatusPoller.fetchFinalSessionStatus(
                    authenticationSessionResponse.sessionID());
            handleSidAuthenticationResult(taraSession, sessionStatus, requestBuilder);
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
            NotificationAuthenticationSessionRequestBuilder requestBuilder) {
        SidAuthenticationResult taraAuthResult = (SidAuthenticationResult) taraSession.getAuthenticationResult();
        String sidSessionId = taraAuthResult.getSidSessionId();
        log.info("SID session id {} authentication result: {}, document number: {}, status: {}",
                value("tara.session.authentication_result.sid_session_id", sidSessionId),
                value("tara.session.authentication_result.sid_end_result", sessionStatus.getResult().getEndResult()),
                value("tara.session.authentication_result.sid_document_number", sessionStatus.getResult().getDocumentNumber()),
                value("tara.session.authentication_result.sid_state", sessionStatus.getState()));

        // TODO (AUT-2604): SidAuthenticationResult fields were previously populated *before* calling responseValidator.validate(),
        //  so that this information would be available in case of validation failure and could be logged with full details.
        //  Since Smart ID v3, this is no longer possible, but the impact of missing information is not known yet.
        //  We need to populate as many taraAuthResult fields as possible before validation. This information needs
        //  to be taken from somewhere else now.
        AuthenticationIdentity authIdentity = responseValidator.validate(
                sessionStatus,
                requestBuilder.getAuthenticationSessionRequest(),
                smartIdConfigurationProperties.getSchemaName());
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
        ErrorCode errorCode = SmartIdExceptionTranslator.getErrorCode(ex);
        taraSession.accept(new AuthenticationFailedSessionUpdate(errorCode));

        if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
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
        if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
            statisticsLogger.logExternalTransaction(taraSession, ex);
        } else {
            statisticsLogger.logExternalTransaction(taraSession);
        }
    }

}
