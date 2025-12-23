package ee.ria.taraauthserver.authentication.smartid.qrcode;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Outcome;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.authentication.smartid.RpChallengeService;
import ee.ria.taraauthserver.authentication.smartid.SmartIdExceptionTranslator;
import ee.ria.taraauthserver.authentication.smartid.SmartIdLanguage;
import ee.ria.taraauthserver.authentication.smartid.SmartIdSessionStatus;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.AuthenticationFailedSessionUpdate;
import ee.ria.taraauthserver.session.update.CancelSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.PollSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.SmartIdAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.TaraSessionUpdate;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.DeviceLinkAuthenticationSessionRequestBuilder;
import ee.sk.smartid.DeviceLinkType;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SessionType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static ee.ria.taraauthserver.session.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.utils.RequestUtils.withMdcAndLocale;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

@Slf4j
@Service
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.qr-code.enabled"
        },
        havingValue = "true"
)
@RequiredArgsConstructor
public class AuthSidQrCodeService {

    private final SmartIdClient smartIdClient;
    private final RpChallengeService rpChallengeService;
    private final SessionRepository<Session> sessionRepository;
    private final DeviceLinkAuthenticationResponseValidator responseValidator;
    private final Executor applicationTaskExecutor;
    private final SmartIdConfigurationProperties smartIdConfigurationProperties;
    private final StatisticsLogger statisticsLogger;
    private final Clock clock;

    public void startAuthentication(@NonNull TaraSession session) {
        assertSessionInState(session, INIT_AUTH_PROCESS);
        updateSession(session, new InitSmartIdQrCodeAuthenticationSessionUpdate());
        CompletableFuture.runAsync(withMdcAndLocale(() -> doAuthenticate(session)), applicationTaskExecutor)
                .exceptionally(withMdcAndLocale((e) -> {
                    log.error("Smart-ID QR code flow background task failed", e);
                    return null;
                }));
    }

    public void cancelAuthentication(@NonNull TaraSession session) {
        assertSessionInState(session, Set.of(INIT_SID_QR_CODE, POLL_SID_QR_CODE));
        updateSession(session, new CancelSmartIdQrCodeAuthenticationSessionUpdate());
    }

    public String getDeviceLink(@NonNull TaraSession session, @NonNull Locale locale) {
        assertSessionInState(session, Set.of(INIT_SID_QR_CODE, POLL_SID_QR_CODE));
        TaraSession.SmartIdQrCodeSession smartIdSession = session.getSmartIdQrCodeSession();
        if (smartIdSession == null) {
            return null;
        }
        Duration elapsedTime = getElapsedTime(smartIdSession);
        SmartIdLanguage language = SmartIdLanguage.fromLocale(locale);
        if (language == null) {
            throw new IllegalArgumentException("Invalid language provided");
        }
        URI deviceLink = smartIdClient.createDynamicContent()
                .withSchemeName(smartIdConfigurationProperties.getSchemaName())
                .withDeviceLinkBase(smartIdSession.getDeviceLinkBase())
                .withDeviceLinkType(DeviceLinkType.QR_CODE)
                .withSessionType(SessionType.AUTHENTICATION)
                .withSessionToken(smartIdSession.getSessionToken())
                .withElapsedSeconds(elapsedTime.getSeconds())
                .withLang(language.getValue())
                .withDigest(smartIdSession.getRpChallenge().toBase64EncodedValue())
                .withInteractions(smartIdSession.getInteractions())
                .withRelyingPartyName(smartIdSession.getRelyingPartyName())
                .buildDeviceLink(smartIdSession.getSessionSecret());
        return deviceLink.toString();
    }

    private void doAuthenticate(@NonNull TaraSession session) {
        try {
            initSmartIdSession(session);
            AuthenticationIdentity authenticationIdentity = fetchSmartIdAuthenticationResult(session);
            updateSession(session, new SmartIdAuthenticationSuccessfulSessionUpdate(
                    authenticationIdentity, smartIdConfigurationProperties.getLevelOfAssurance()
            ));
            logSuccessToStatisticsLog(session);
        } catch (Exception e) {
            ErrorCode errorCode = SmartIdExceptionTranslator.getErrorCode(e);
            if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
                log.atError()
                        .addMarker(append("error.code", errorCode.name()))
                        .setCause(e)
                        .log("Smart-ID authentication exception: {}",
                                value("error.message", e.getMessage()));
            } else {
                log.atWarn()
                        .log("Smart-ID authentication failed: {}, Error code: {}",
                                value("error.message", e.getMessage()),
                                value("error.code", errorCode.name()));
            }
            updateSession(session, new AuthenticationFailedSessionUpdate(errorCode));
            logErrorToStatisticsLog(session, errorCode, e);
        }
    }

    private Duration getElapsedTime(TaraSession.SmartIdQrCodeSession smartIdSession) {
        Duration result = Duration.between(smartIdSession.getStartTime(), Instant.now(clock));
        if (result.isNegative()) {
            return Duration.ZERO;
        }
        return result;
    }

    private void initSmartIdSession(@NonNull TaraSession session) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(ElasticApmUtil.currentTimeMicros(clock));
        try(Scope scope = span.activate()) {
            Optional<RelyingParty> relyingParty = session.getSmartIdRelyingParty();
            String shortName = defaultIfNull(
                    session.getOriginalClient().getTranslatedShortName(),
                    smartIdConfigurationProperties.getDisplayText());
            RpChallenge rpChallenge = rpChallengeService.getRpChallenge();
            List<DeviceLinkInteraction> interactions = List.of(DeviceLinkInteraction.confirmationMessage(shortName));

            DeviceLinkAuthenticationSessionRequestBuilder initSmartIdSessionBuilder = smartIdClient
                    .createDeviceLinkAuthentication()
                    .withRpChallenge(rpChallenge.toBase64EncodedValue())
                    .withInteractions(interactions)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
            relyingParty.ifPresent(it -> initSmartIdSessionBuilder
                    .withRelyingPartyName(it.getName())
                    .withRelyingPartyUUID(it.getUuid()));

            DeviceLinkSessionResponse initSmartIdSessionResponse = initSmartIdSessionBuilder.initAuthenticationSession();
            DeviceLinkAuthenticationSessionRequest initSmartIdSessionRequest =
                    initSmartIdSessionBuilder.getAuthenticationSessionRequest();
            updateSession(session, new PollSmartIdQrCodeAuthenticationSessionUpdate(
                    Instant.now(clock),
                    rpChallenge,
                    initSmartIdSessionRequest,
                    initSmartIdSessionResponse));
        } catch (Exception e) {
            span.captureException(e);
            span.setOutcome(Outcome.FAILURE);
            throw e;
        } finally {
            span.end(ElasticApmUtil.currentTimeMicros(clock));
        }
    }

    private AuthenticationIdentity fetchSmartIdAuthenticationResult(@NonNull TaraSession session) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(ElasticApmUtil.currentTimeMicros(clock));
        try(Scope scope = span.activate()) {
            TaraSession.SmartIdQrCodeSession smartIdQrCodeSession = session.getSmartIdQrCodeSession();
            String sessionId = smartIdQrCodeSession.getSessionId();
            SessionStatus sessionStatus = smartIdClient.getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
            if (!sessionStatus.getState().equalsIgnoreCase(SmartIdSessionStatus.COMPLETE)) {
                throw new IllegalStateException(
                        "Expected Smart-ID session to be in '" + SmartIdSessionStatus.COMPLETE + "' state.");
            }
            DeviceLinkAuthenticationSessionRequest request = smartIdQrCodeSession.getRequest();
            return responseValidator.validate(
                    sessionStatus, request, null, smartIdConfigurationProperties.getSchemaName());
        } catch (Exception e) {
            span.captureException(e);
            span.setOutcome(Outcome.FAILURE);
            throw e;
        } finally {
            span.end(ElasticApmUtil.currentTimeMicros(clock));
        }
    }

    private void updateSession(@NonNull TaraSession taraSession, TaraSessionUpdate update) {
        taraSession.accept(update);
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session == null) {
            throw new IllegalStateException("Session \"%s\" not found".formatted(taraSession.getSessionId()));
        }
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void logSuccessToStatisticsLog(TaraSession session) {
        statisticsLogger.logExternalTransaction(session);
    }

    private void logErrorToStatisticsLog(TaraSession session, ErrorCode errorCode, Exception e) {
        if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
            statisticsLogger.logExternalTransaction(session, e);
        } else {
            statisticsLogger.logExternalTransaction(session);
        }
    }

}
