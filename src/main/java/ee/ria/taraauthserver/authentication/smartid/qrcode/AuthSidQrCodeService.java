package ee.ria.taraauthserver.authentication.smartid.qrcode;

import ee.ria.taraauthserver.authentication.smartid.SmartIdClientFacade;
import ee.ria.taraauthserver.authentication.smartid.SmartIdDeviceLinkSession;
import ee.ria.taraauthserver.authentication.smartid.SmartIdExceptionTranslator;
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
import ee.sk.smartid.AuthenticationIdentity;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

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
            updateSession(session, new PollSmartIdQrCodeAuthenticationSessionUpdate(smartIdDeviceLinkSession));

            AuthenticationIdentity authenticationIdentity = smartIdClientFacade.fetchSmartIdAuthenticationResult(
                    smartIdDeviceLinkSession);
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
