package ee.ria.taraauthserver.authentication.smartid.qrcode;

import ee.ria.taraauthserver.authentication.smartid.SmartIdClientFacade;
import ee.ria.taraauthserver.authentication.smartid.SmartIdDeviceLinkSession;
import ee.ria.taraauthserver.authentication.smartid.SmartIdExceptionTranslator;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.IgniteClusterNodes;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.AuthenticationFailedSessionUpdate;
import ee.ria.taraauthserver.session.update.CancelSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.PollSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.ResumeSmartIdQrCodePollingSessionUpdate;
import ee.ria.taraauthserver.session.update.SmartIdAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.TaraSessionUpdate;
import ee.sk.smartid.AuthenticationIdentity;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
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

    private final SmartIdClientFacade smartIdClientFacade;
    private final SessionRepository<Session> sessionRepository;
    private final Executor applicationTaskExecutor;
    private final SmartIdConfigurationProperties smartIdConfigurationProperties;
    private final StatisticsLogger statisticsLogger;
    private final Clock clock;
    private final IgniteClusterNodes igniteClusterNodes;

    public void startAuthentication(@NonNull TaraSession session) {
        assertSessionInState(session, INIT_AUTH_PROCESS);
        updateSession(session, new InitSmartIdQrCodeAuthenticationSessionUpdate(igniteClusterNodes.localNodeId()));
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
        SmartIdDeviceLinkSession smartIdSession = session.getSmartIdQrCodeSession();
        if (smartIdSession == null) {
            return null;
        }
        return smartIdClientFacade.getQrCodeDeviceLink(smartIdSession, locale);
    }

    private void doAuthenticate(@NonNull TaraSession session) {
        try {
            SmartIdDeviceLinkSession smartIdDeviceLinkSession = smartIdClientFacade.initDeviceLinkSession(
                    session.getOriginalClient().getTranslatedShortName(),
                    session.getSmartIdRelyingParty().orElse(null));
            updateSession(session, new PollSmartIdQrCodeAuthenticationSessionUpdate(smartIdDeviceLinkSession, Instant.now(clock)));

            pollAuthenticationResult(session, smartIdDeviceLinkSession);
        } catch (Exception e) {
            handleAuthenticationFailure(session, e);
        }
    }

    private void pollAuthenticationResult(@NonNull TaraSession session, @NonNull SmartIdDeviceLinkSession smartIdDeviceLinkSession) {
        AuthenticationIdentity authenticationIdentity = smartIdClientFacade.fetchSmartIdAuthenticationResult(
                smartIdDeviceLinkSession);
        session.setAuthFlowEndTime(Instant.now(clock));
        updateSession(session, new SmartIdAuthenticationSuccessfulSessionUpdate(
                authenticationIdentity, smartIdConfigurationProperties.getLevelOfAssurance()
        ));
        logSuccessToStatisticsLog(session);
    }

    private void handleAuthenticationFailure(@NonNull TaraSession session, Exception e) {
        if (session.getAuthFlowEndTime() == null) {
            session.setAuthFlowEndTime(Instant.now(clock));
        }
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
        session.accept(new AuthenticationFailedSessionUpdate(errorCode));
        logErrorToStatisticsLog(session, errorCode, e);
        saveSession(session);
    }

    public void resumePollingIfPollingNodeHasLeftCluster(@NonNull TaraSession session) {
        if (session.getState() != INIT_SID_QR_CODE && session.getState() != POLL_SID_QR_CODE) {
            return;
        }
        String pollingNodeId = session.getPollingNodeId();
        if (pollingNodeId == null || !igniteClusterNodes.hasLeftCluster(pollingNodeId)) {
            return;
        }
        SmartIdDeviceLinkSession smartIdDeviceLinkSession = session.getSmartIdQrCodeSession();
        if (smartIdDeviceLinkSession == null) {
            log.warn("Cannot resume Smart-ID session status polling, the Smart-ID session was not created before the polling node left the cluster: node={}",
                    pollingNodeId);
            return;
        }
        log.warn("Resuming Smart-ID session status polling on this node, previous polling node left the cluster: session={}, node={}",
                value("tara.session.sid_authentication_result.sid_session_id", smartIdDeviceLinkSession.sessionId()), pollingNodeId);
        updateSession(session, new ResumeSmartIdQrCodePollingSessionUpdate(igniteClusterNodes.localNodeId()));
        resumePollingInBackground(session, smartIdDeviceLinkSession);
    }

    private void resumePollingInBackground(@NonNull TaraSession session, @NonNull SmartIdDeviceLinkSession smartIdDeviceLinkSession) {
        CompletableFuture.runAsync(withMdcAndLocale(() -> {
            try {
                pollAuthenticationResult(session, smartIdDeviceLinkSession);
            } catch (Exception e) {
                handleAuthenticationFailure(session, e);
            }
        }), applicationTaskExecutor)
                .exceptionally(withMdcAndLocale((e) -> {
                    log.error("Smart-ID QR code resumed polling task failed", e);
                    return null;
                }));
    }

    private void updateSession(@NonNull TaraSession taraSession, TaraSessionUpdate update) {
        taraSession.accept(update);
        saveSession(taraSession);
    }

    private void saveSession(@NonNull TaraSession taraSession) {
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
