package ee.ria.taraauthserver.authentication.eudi;

import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession.StatusEnum;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.OfferResponse;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.EudiConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.EudiPresentationFailedException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.EudiFlow;
import ee.ria.taraauthserver.session.update.CancelEudiAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.EudiAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.EudiDcApiAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.EudiWeb2AppAuthenticationSuccessfulSessionUpdate;
import ee.ria.taraauthserver.session.update.InitEudiDcApiAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitEudiWeb2AppAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.TaraSessionUpdate;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import jakarta.annotation.PostConstruct;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static ee.ria.taraauthserver.authentication.eudi.EudiSpans.inSpan;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_CALLBACK_INVALID;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_CLIENT_NOT_REGISTERED;
import static ee.ria.taraauthserver.error.ErrorCode.EUDI_INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_CALLBACK;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.DC_API;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.WEB2APP;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.logstash.logback.argument.StructuredArguments.value;

/**
 * EUDI wallet authentication through an eudiplo OpenID4VP verifier, in one of two flows (see {@link EudiFlow}). An
 * authentication completes only through the browser that started the login, never by polling eudiplo.
 */
@Slf4j
@Service
@ConditionalOnProperty(value = "tara.auth-methods.eudi-wallet.enabled")
@RequiredArgsConstructor
public class AuthEudiService {
    private static final String RELATIVE_CALLBACK_URL = "auth/eudi/callback";

    private final EudiploClient eudiploClient;
    private final EudiConfigurationProperties eudiConfigurationProperties;
    private final AuthConfigurationProperties authConfigurationProperties;
    private final StatisticsLogger statisticsLogger;
    private final Clock clock;

    private String web2AppRedirectUri;
    private String dcApiExpectedOrigin;

    @PostConstruct
    void resolveWalletFacingUrls() throws URISyntaxException {
        URL siteOrigin = authConfigurationProperties.getSiteOrigin();
        dcApiExpectedOrigin = siteOrigin.toString();
        web2AppRedirectUri = siteOrigin.toURI().resolve(RELATIVE_CALLBACK_URL).toString();
    }

    public String startWeb2AppAuthSession(@NonNull TaraSession taraSession) {
        assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        String clientId = resolveClientId(taraSession);
        String presentationConfigId = resolvePresentationConfigId(taraSession, clientId);

        OfferResponse offer = inSpan(clock, "init", ElasticApmUtil.currentMethodName(),
                () -> eudiploClient.createPresentationOffer(presentationConfigId, web2AppRedirectUri));
        String presentationSessionId = offer.getSession();
        String walletLink = offer.getUri();
        if (StringUtils.isBlank(walletLink)) {
            throw new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                    "eudiplo did not return a WEB2APP wallet link for presentation session " + presentationSessionId,
                    null);
        }

        logAuthenticationStarted(WEB2APP, presentationSessionId, clientId, presentationConfigId);
        updateSession(taraSession,
                new InitEudiWeb2AppAuthenticationSessionUpdate(presentationSessionId, Instant.now(clock)));
        return walletLink;
    }

    public String startDcApiAuthSession(@NonNull TaraSession taraSession) {
        assertSessionInState(taraSession, INIT_AUTH_PROCESS);
        String clientId = resolveClientId(taraSession);
        String presentationConfigId = resolvePresentationConfigId(taraSession, clientId);

        OfferResponse offer = inSpan(clock, "init", ElasticApmUtil.currentMethodName(),
                () -> eudiploClient.createDcApiPresentationOffer(presentationConfigId, dcApiExpectedOrigin));
        String presentationSessionId = offer.getSession();
        EudiploSession presentationSession = fetchPresentationSession(presentationSessionId);
        String requestObject = presentationSession.getRequestObject();
        String walletNonce = presentationSession.getWalletNonce();
        if (StringUtils.isAnyBlank(requestObject, walletNonce)) {
            throw new ServiceNotAvailableException(EUDI_INTERNAL_ERROR,
                    "eudiplo presentation session %s has no request object or wallet nonce"
                            .formatted(presentationSessionId),
                    null);
        }

        logAuthenticationStarted(DC_API, presentationSessionId, clientId, presentationConfigId);
        updateSession(taraSession,
                new InitEudiDcApiAuthenticationSessionUpdate(presentationSessionId, walletNonce, Instant.now(clock)));
        return requestObject;
    }

    public void cancelAuthentication(@NonNull TaraSession taraSession) {
        assertSessionInState(taraSession, Set.of(WAITING_EUDI_CALLBACK, WAITING_EUDI_DC_API_RESPONSE));
        updateSession(taraSession, new CancelEudiAuthenticationSessionUpdate());
    }

    public void completeWeb2AppAuthentication(@NonNull TaraSession taraSession, String responseCode) {
        assertSessionInState(taraSession, WAITING_EUDI_CALLBACK);
        String presentationSessionId = taraSession.getEudiSession().getPresentationSessionId();
        try {
            EudiploSession presentationSession = fetchPresentationSession(presentationSessionId);
            verifyWeb2AppPresentation(presentationSession, presentationSessionId, responseCode);
            completeAuthentication(taraSession, presentationSession, presentationSessionId, WEB2APP);
        } catch (Exception e) {
            throw failAuthentication(taraSession, e);
        }
    }

    public void pollWeb2AppAuthentication(@NonNull TaraSession taraSession) {
        assertSessionInState(taraSession, WAITING_EUDI_CALLBACK);
        String presentationSessionId = taraSession.getEudiSession().getPresentationSessionId();
        try {
            pollPresentationSession(presentationSessionId).ifPresent(this::assertPresentationNotFailed);
        } catch (EudiPresentationFailedException e) {
            throw failAuthentication(taraSession, e);
        }
    }

    public void completeDcApiAuthentication(@NonNull TaraSession taraSession, WalletResponse walletResponse) {
        assertSessionInState(taraSession, WAITING_EUDI_DC_API_RESPONSE);
        TaraSession.EudiSession eudiSession = taraSession.getEudiSession();
        String presentationSessionId = eudiSession.getPresentationSessionId();
        try {
            requireResponseOrError(walletResponse, presentationSessionId);
            boolean accepted = inSpan(clock, "response", ElasticApmUtil.currentMethodName(),
                    () -> eudiploClient.submitWalletResponse(walletResponse, eudiSession.getWalletNonce()));
            EudiploSession presentationSession = fetchPresentationSession(presentationSessionId);
            verifyDcApiPresentation(presentationSession, presentationSessionId, walletResponse, accepted);
            completeAuthentication(taraSession, presentationSession, presentationSessionId, DC_API);
        } catch (Exception e) {
            throw failAuthentication(taraSession, e);
        }
    }

    private static String resolveClientId(TaraSession taraSession) {
        TaraSession.LoginRequestInfo loginRequestInfo = taraSession.getLoginRequestInfo();
        if (loginRequestInfo == null || loginRequestInfo.getClientId() == null) {
            throw new BadRequestException(EUDI_CLIENT_NOT_REGISTERED,
                    "Unable to resolve client id of the EUDI wallet authentication request");
        }
        return loginRequestInfo.getClientId();
    }

    private static String resolvePresentationConfigId(TaraSession taraSession, String clientId) {
        return taraSession.getEudiPresentationConfigId()
                .orElseThrow(() -> new BadRequestException(EUDI_CLIENT_NOT_REGISTERED,
                        "No eudi_settings.presentation_config_id in metadata of client \"%s\"".formatted(clientId)));
    }

    private static void logAuthenticationStarted(EudiFlow flow, String presentationSessionId, String clientId,
                                                 String presentationConfigId) {
        log.info("Started EUDI wallet {} presentation session {} for client {} using eudiplo presentation configuration {}",
                value("tara.session.eudi.flow", flow.name()),
                value("tara.session.eudi.presentation_session_id", presentationSessionId),
                value("tara.session.eudi.client_id", clientId),
                value("tara.session.eudi.presentation_config_id", presentationConfigId));
    }

    private EudiploSession fetchPresentationSession(String presentationSessionId) {
        return inSpan(clock, "poll", ElasticApmUtil.currentMethodName(),
                () -> eudiploClient.getPresentationSession(presentationSessionId));
    }

    private Optional<EudiploSession> pollPresentationSession(String presentationSessionId) {
        try {
            return Optional.of(inSpan(clock, "poll", ElasticApmUtil.currentMethodName(),
                    () -> eudiploClient.pollPresentationSession(presentationSessionId)));
        } catch (Exception e) {
            log.warn("EUDI wallet presentation session {} status poll failed: {}",
                    value("tara.session.eudi.presentation_session_id", presentationSessionId),
                    value("error.message", e.getMessage()));
            return Optional.empty();
        }
    }

    private void verifyWeb2AppPresentation(EudiploSession presentationSession, String presentationSessionId,
                                           String responseCode) {
        assertPresentationNotFailed(presentationSession);
        if (presentationSession.getStatus() != StatusEnum.COMPLETED) {
            throw callbackInvalid("EUDI wallet callback arrived, but eudiplo presentation session %s is in status %s",
                    presentationSessionId, presentationSession.getStatus());
        }
        String expectedResponseCode = presentationSession.getResponseCode();
        if (responseCode == null || expectedResponseCode == null
                || !MessageDigest.isEqual(expectedResponseCode.getBytes(UTF_8), responseCode.getBytes(UTF_8))) {
            throw callbackInvalid("EUDI wallet callback response code does not match eudiplo presentation session %s",
                    presentationSessionId);
        }
    }

    private static void requireResponseOrError(WalletResponse walletResponse, String presentationSessionId) {
        if (walletResponse == null || (walletResponse.response() == null) == (walletResponse.error() == null)) {
            throw callbackInvalid(
                    "EUDI wallet response for presentation session %s must carry exactly one of response and error",
                    presentationSessionId);
        }
    }

    private void verifyDcApiPresentation(EudiploSession presentationSession, String presentationSessionId,
                                         WalletResponse walletResponse, boolean accepted) {
        assertPresentationNotFailed(presentationSession);
        if (presentationSession.getStatus() != StatusEnum.COMPLETED) {
            throw callbackInvalid("eudiplo %s the wallet response, but presentation session %s is in status %s",
                    accepted ? "accepted" : "rejected", presentationSessionId, presentationSession.getStatus());
        }
        if (!accepted || walletResponse.error() != null) {
            throw callbackInvalid(
                    "eudiplo presentation session %s was completed by a response that this browser did not submit",
                    presentationSessionId);
        }
    }

    private void assertPresentationNotFailed(EudiploSession presentationSession) {
        ErrorCode errorCode = EudiExceptionTranslator.getErrorCodeForSession(presentationSession, Instant.now(clock));
        if (errorCode != null) {
            throw new EudiPresentationFailedException(errorCode,
                    EudiExceptionTranslator.describeEndedSession(presentationSession));
        }
    }

    private static EudiPresentationFailedException callbackInvalid(String message, Object... args) {
        return new EudiPresentationFailedException(EUDI_CALLBACK_INVALID, message.formatted(args));
    }

    private void completeAuthentication(TaraSession taraSession, EudiploSession presentationSession,
                                        String presentationSessionId, EudiFlow flow) {
        taraSession.setAuthFlowEndTime(Instant.now(clock));

        updateSession(taraSession, createSuccessfulUpdate(presentationSession, flow));
        statisticsLogger.logExternalTransaction(taraSession);
        log.info("EUDI wallet {} presentation session {} verified",
                value("tara.session.eudi.flow", flow.name()),
                value("tara.session.eudi.presentation_session_id", presentationSessionId));
    }

    private EudiAuthenticationSuccessfulSessionUpdate createSuccessfulUpdate(
            EudiploSession completedSession, EudiFlow flow) {
        EudiPidClaims pid = EudiPidClaims.from(completedSession);
        LevelOfAssurance levelOfAssurance = eudiConfigurationProperties.getLevelOfAssurance();
        return switch (flow) {
            case WEB2APP -> new EudiWeb2AppAuthenticationSuccessfulSessionUpdate(
                    pid.personalAdministrativeNumber(), pid.issuingCountry(), pid.givenName(), pid.familyName(),
                    pid.birthDate(), levelOfAssurance);
            case DC_API -> new EudiDcApiAuthenticationSuccessfulSessionUpdate(
                    pid.personalAdministrativeNumber(), pid.issuingCountry(), pid.givenName(), pid.familyName(),
                    pid.birthDate(), levelOfAssurance);
        };
    }

    private RuntimeException failAuthentication(TaraSession taraSession, Exception e) {
        ErrorCode errorCode = EudiExceptionTranslator.getErrorCode(e);
        boolean technicalError = EudiExceptionTranslator.isTechnicalError(errorCode);
        // Kept if set: the success path sets it before reading the PID claims, which can still fail.
        if (taraSession.getAuthFlowEndTime() == null) {
            taraSession.setAuthFlowEndTime(Instant.now(clock));
        }
        taraSession.getAuthenticationResult().setErrorCode(errorCode);
        statisticsLogger.logExternalTransaction(taraSession, technicalError ? e : null);
        return toErrorHandlerException(technicalError, errorCode, e);
    }

    private static RuntimeException toErrorHandlerException(boolean technicalError, ErrorCode errorCode, Exception e) {
        if (e instanceof ServiceNotAvailableException serviceNotAvailableException) {
            return serviceNotAvailableException;
        }
        return technicalError
                ? new ServiceNotAvailableException(errorCode, e.getMessage(), e)
                : new BadRequestException(errorCode, e.getMessage());
    }

    private void updateSession(@NonNull TaraSession taraSession, TaraSessionUpdate update) {
        taraSession.accept(update);
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
    }

}
