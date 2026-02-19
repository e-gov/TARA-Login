package ee.ria.taraauthserver.authentication.smartid.web2app;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.authentication.common.AuthenticationDisplayTextBuilder;
import ee.ria.taraauthserver.authentication.smartid.RpChallengeService;
import ee.ria.taraauthserver.authentication.smartid.SmartIdExceptionTranslator;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.SidCountryNotAllowedException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.SidAuthenticationResult;
import ee.ria.taraauthserver.session.update.CreateNewSmartIdAuthenticationResultSessionUpdate;
import ee.ria.taraauthserver.session.update.FailSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.PollSmartIdWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.SaveSmartIdWeb2AppSessionStatusSessionUpdate;
import ee.ria.taraauthserver.session.update.SmartIdAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.TaraSessionUpdate;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import ee.ria.taraauthserver.utils.LanguageUtil;
import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.DeviceLinkAuthenticationSessionRequestBuilder;
import ee.sk.smartid.DeviceLinkType;
import ee.sk.smartid.ErrorResultHandler;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SessionType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.common.devicelink.CallbackUrl;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.CallbackUrlUtil;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static co.elastic.apm.api.Outcome.FAILURE;
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

    private static final String RELATIVE_CALLBACK_URL = "auth/sid/web2app/callback";

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

    @Autowired
    private AuthenticationDisplayTextBuilder authenticationDisplayTextBuilder;

    public URI startSidAuthSession(@NonNull TaraSession taraSession) throws URISyntaxException {
        RpChallenge rpChallenge = rpChallengeService.getRpChallenge();
        updateSession(taraSession, new InitSmartIdWeb2AppAuthenticationSessionUpdate());

        RelyingParty relyingParty = taraSession.getSmartIdRelyingParty()
                .orElse(smartIdConfigurationProperties.getRelyingParty());
        String baseShortName = defaultIfNull(
                taraSession.getOriginalClient().getTranslatedShortName(),
                smartIdConfigurationProperties.getDisplayText());
        String shortName = authenticationDisplayTextBuilder.buildLoginDisplayText(baseShortName);
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

        DeviceLinkSessionResponse sessionResponse = initAuthentication(taraSession, requestBuilder, callbackUrlWithToken);
        DeviceLinkAuthenticationSessionRequest sessionRequest = requestBuilder.getAuthenticationSessionRequest();
        String language = LanguageUtil.toIso3(taraSession.getChosenLanguage());
        URI deviceLink = createDeviceLink(
                sessionRequest.interactions(),
                sessionResponse,
                language,
                rpChallenge,
                callbackUrlWithToken.initialCallbackUri().toString());
        startPollingAuthenticationResult(taraSession);
        return deviceLink;
    }

    public void handleFinalAuthenticationResult(
            @NonNull TaraSession taraSession,
            SessionStatus sessionStatus,
            String userChallengeVerifier,
            String sessionSecretDigest,
            String urlToken) {
        try {
            AuthenticationIdentity authIdentity = validateFinalAuthenticationResult(
                    taraSession, sessionStatus, userChallengeVerifier, sessionSecretDigest, urlToken);
            validateAuthenticationCountry(authIdentity);
            updateSession(taraSession, new SmartIdAuthenticationSuccessfulSessionUpdate(
                    authIdentity, smartIdConfigurationProperties.getLevelOfAssurance()));
            logSuccessToStatisticsLog(taraSession);
        } catch (Exception e) {
            handleSidAuthenticationException(taraSession, e);
            logErrorToStatisticsLog(taraSession, e);
        } finally {
            taraSession.setSmartIdWeb2AppSession(null);
        }
    }

    public static void assertCallbackUrlTokenMatchesInitialToken(TaraSession taraSession, String initialUrlToken) {
        if (initialUrlToken == null
                || taraSession.getSmartIdWeb2AppSession() == null
                || !initialUrlToken.equals(taraSession.getSmartIdWeb2AppSession().getUrlToken())) {
            throw new SmartIdClientException("Token from actual callback URL does not match token from initial callback URL");
        }
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
            DeviceLinkAuthenticationSessionRequestBuilder requestBuilder,
            CallbackUrl callbackUrlWithToken) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(now().plus(200, MILLIS).toEpochMilli() * 1_000);
        try (final Scope ignored = span.activate()) {
            DeviceLinkSessionResponse authenticationSessionResponse = requestBuilder.initAuthenticationSession();
            String sidSessionId = authenticationSessionResponse.sessionID();
            log.info("Initiated Smart-ID Web2App session with id: {}",
                    value("tara.session.authentication_result.sid_session_id", sidSessionId));
            updateSession(taraSession, new PollSmartIdWeb2AppAuthenticationSessionUpdate(
                    sidSessionId,
                    authenticationSessionResponse.sessionSecret(),
                    requestBuilder.getAuthenticationSessionRequest(),
                    callbackUrlWithToken.urlToken()
            ));
            updateSession(taraSession, new CreateNewSmartIdAuthenticationResultSessionUpdate(sidSessionId));
            return authenticationSessionResponse;
        } catch (Exception e) {
            updateSession(taraSession, new CreateNewSmartIdAuthenticationResultSessionUpdate(null));
            handleSidAuthenticationException(taraSession, e);
            logErrorToStatisticsLog(taraSession, e);
            throw e;
        } finally {
            span.end();
        }
    }

    private void updateSession(@NonNull TaraSession taraSession, TaraSessionUpdate update) {
        taraSession.accept(update);
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session != null) {
            session.setAttribute(TARA_SESSION, taraSession);
            sessionRepository.save(session);
        } else {
            log.error("Session correlated with this Smart-ID polling process was not found: {}", taraSession.getSessionId());
        }
    }

    private void startPollingAuthenticationResult(TaraSession taraSession) {
        CompletableFuture.supplyAsync(
                withMdc(() -> {
                    pollUntilFinalAuthenticationResult(taraSession);
                    return null; // This is only needed to support the existing signature of withMdc() method
                }),
                applicationTaskExecutor
        );
    }

    private void pollUntilFinalAuthenticationResult(@NonNull TaraSession taraSession) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll");
        span.setName(ElasticApmUtil.currentMethodName());
        span.setStartTimestamp(
                now()
                        .plus(200, MILLIS)
                        .minus(smartIdConfigurationProperties.getDelayStatusPollingStart())
                        .toEpochMilli() * 1_000);
        try (final Scope scope = span.activate()) {
            SessionStatusPoller sessionStatusPoller = sidClient.getSessionStatusPoller();
            log.info("Starting Smart-ID session status polling with id: {}",
                    value("tara.session.sid_authentication_result.sid_session_id", taraSession.getSmartIdWeb2AppSession().getSessionId()));
            SessionStatus sessionStatus = sessionStatusPoller.fetchFinalSessionStatus(taraSession.getSmartIdWeb2AppSession().getSessionId());
            validateSessionStatus(sessionStatus);
            updateSession(taraSession, new SaveSmartIdWeb2AppSessionStatusSessionUpdate(sessionStatus));
        } catch (Exception ex) {
            handleSidAuthenticationException(taraSession, ex);
            logErrorToStatisticsLog(taraSession, ex);
        } finally {
            span.end();
        }
    }

    private static void validateSessionStatus(@NonNull SessionStatus sessionStatus) {
        if (!"OK".equals(sessionStatus.getResult().getEndResult())) {
            ErrorResultHandler.handle(sessionStatus.getResult());
        }
    }

    private AuthenticationIdentity validateFinalAuthenticationResult(
            TaraSession taraSession,
            SessionStatus sessionStatus,
            String userChallengeVerifier,
            String sessionSecretDigest,
            String urlToken) {
        SidAuthenticationResult taraAuthResult = (SidAuthenticationResult) taraSession.getAuthenticationResult();
        // TODO (AUT-2604): SidAuthenticationResult fields were previously populated *before* calling responseValidator.validate(),
        //  so that this information would be available in case of validation failure and could be logged with full details.
        //  Since Smart ID v3, this is no longer possible, but the impact of missing information is not known yet.
        //  Now we populate these fields in class SmartIdAuthenticationSuccessfulSessionUpdate, when
        //  responseValidator.validate() has already been run.
        //  We need to populate as many taraAuthResult fields as possible before validation. This information needs
        //  to be taken from somewhere else now.
        String sidSessionId = taraAuthResult.getSidSessionId();
        log.info("SID session id {} authentication result: {}, document number: {}, status: {}",
                value("tara.session.authentication_result.sid_session_id", sidSessionId),
                value("tara.session.authentication_result.sid_end_result", sessionStatus.getResult().getEndResult()),
                value("tara.session.authentication_result.sid_document_number", sessionStatus.getResult().getDocumentNumber()),
                value("tara.session.authentication_result.sid_state", sessionStatus.getState()));
        return validateSessionAndGetIdentity(
                taraSession,
                sessionStatus,
                userChallengeVerifier,
                sessionSecretDigest,
                urlToken);
    }

    private AuthenticationIdentity validateSessionAndGetIdentity(
            TaraSession taraSession,
            SessionStatus sessionStatus,
            String userChallengeVerifier,
            String sessionSecretDigest,
            String urlToken) {
        assertCallbackUrlTokenMatchesInitialToken(taraSession, urlToken);
        CallbackUrlUtil.validateSessionSecretDigest(sessionSecretDigest, taraSession.getSmartIdWeb2AppSession().getSessionSecret());
        return responseValidator.validate(
                sessionStatus,
                taraSession.getSmartIdWeb2AppSession().getAuthenticationSessionRequest(),
                userChallengeVerifier,
                smartIdConfigurationProperties.getSchemaName());
    }

    private void validateAuthenticationCountry(AuthenticationIdentity authIdentity) {
        if (!smartIdConfigurationProperties.isAuthenticationFromCountryAllowed(authIdentity.getCountry())) {
            throw new SidCountryNotAllowedException(authIdentity.getCountry());
        }
    }

    private void handleSidAuthenticationException(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = SmartIdExceptionTranslator.getErrorCode(ex);
        if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
            log.error(append("error.code", errorCode.name()), "Smart-ID authentication exception: {}", ex.getMessage(), ex);
        } else {
            log.warn("Smart-ID authentication failed: {}, Error code: {}", value("error.message", ex.getMessage()), value("error.code", errorCode.name()));
        }
        updateSession(taraSession, new FailSmartIdWeb2AppAuthenticationSessionUpdate(errorCode));

        Span span = ElasticApm.currentSpan();
        span.setOutcome(FAILURE);
        span.captureException(ex);
    }

    private void logSuccessToStatisticsLog(TaraSession session) {
        statisticsLogger.logExternalTransaction(session);
    }

    private void logErrorToStatisticsLog(TaraSession taraSession, Exception ex) {
        ErrorCode errorCode = SmartIdExceptionTranslator.getErrorCode(ex);
        if (SmartIdExceptionTranslator.isTechnicalError(errorCode)) {
            statisticsLogger.logExternalTransaction(taraSession, ex);
        } else {
            statisticsLogger.logExternalTransaction(taraSession);
        }
    }

}
