package ee.ria.taraauthserver.authentication.smartid;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Outcome;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.authentication.RelyingParty;
import ee.ria.taraauthserver.authentication.common.AuthenticationDisplayTextFactory;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.exceptions.SidCountryNotAllowedException;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import ee.ria.taraauthserver.utils.LanguageUtil;
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
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
@Slf4j
public class SmartIdClientFacade {

    private final SmartIdClient smartIdClient;
    private final RpChallengeService rpChallengeService;
    private final SmartIdConfigurationProperties smartIdConfigurationProperties;
    private final AuthenticationDisplayTextFactory smartIdDisplayTextFactory;
    private final DeviceLinkAuthenticationResponseValidator responseValidator;
    private final Clock clock;

    public SmartIdDeviceLinkSession initDeviceLinkSession(String clientDisplayName, RelyingParty relyingParty) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(ElasticApmUtil.currentTimeMicros(clock));
        try (Scope scope = span.activate()) {
            String displayText = smartIdDisplayTextFactory.createLoginDisplayText(clientDisplayName);
            RpChallenge rpChallenge = rpChallengeService.getRpChallenge();
            List<DeviceLinkInteraction> interactions = List.of(DeviceLinkInteraction.confirmationMessage(displayText));

            DeviceLinkAuthenticationSessionRequestBuilder initSmartIdSessionBuilder = smartIdClient
                    .createDeviceLinkAuthentication()
                    .withRpChallenge(rpChallenge.toBase64EncodedValue())
                    .withInteractions(interactions)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
            if (relyingParty != null) {
                initSmartIdSessionBuilder
                        .withRelyingPartyName(relyingParty.getName())
                        .withRelyingPartyUUID(relyingParty.getUuid());
            }
            DeviceLinkSessionResponse initSessionResponse = initSmartIdSessionBuilder.initAuthenticationSession();
            DeviceLinkAuthenticationSessionRequest initSessionRequest =
                    initSmartIdSessionBuilder.getAuthenticationSessionRequest();
            log.info("Started Smart-ID session {}", initSessionResponse.sessionID());
            return new SmartIdDeviceLinkSession(
                    Instant.now(clock),
                    rpChallenge,
                    initSessionRequest,
                    initSessionResponse
            );
        } catch (Exception e) {
            span.captureException(e);
            span.setOutcome(Outcome.FAILURE);
            throw e;
        } finally {
            span.end(ElasticApmUtil.currentTimeMicros(clock));
        }
    }

    public AuthenticationIdentity fetchSmartIdAuthenticationResult(@NonNull SmartIdDeviceLinkSession session) {
        Span span = ElasticApm.currentSpan().startSpan("app", "SID", "poll")
                .setName(ElasticApmUtil.currentMethodName())
                .setStartTimestamp(ElasticApmUtil.currentTimeMicros(clock));
        try (Scope scope = span.activate()) {
            String sessionId = session.sessionId();
            SessionStatus sessionStatus = smartIdClient.getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
            if (!sessionStatus.getState().equalsIgnoreCase(SmartIdSessionStatus.COMPLETE)) {
                throw new IllegalStateException(
                        "Expected Smart-ID session to be in '" + SmartIdSessionStatus.COMPLETE + "' state.");
            }
            log.info("Received final Smart-ID session {} status: {}",
                    sessionId, sessionStatus.getResult().getEndResult());
            DeviceLinkAuthenticationSessionRequest request = session.request();
            AuthenticationIdentity result = responseValidator.validate(
                    sessionStatus, request, null, smartIdConfigurationProperties.getSchemaName());
            validateAuthenticationCountry(result);
            return result;
        } catch (Exception e) {
            span.captureException(e);
            span.setOutcome(Outcome.FAILURE);
            throw e;
        } finally {
            span.end(ElasticApmUtil.currentTimeMicros(clock));
        }
    }

    private void validateAuthenticationCountry(AuthenticationIdentity authIdentity) {
        if (!smartIdConfigurationProperties.isAuthenticationFromCountryAllowed(authIdentity.getCountry())) {
            throw new SidCountryNotAllowedException(authIdentity.getCountry());
        }
    }

    public String getQrCodeDeviceLink(@NonNull SmartIdDeviceLinkSession session, @NonNull Locale locale) {
        Duration elapsedTime = getElapsedTime(session);
        String language = LanguageUtil.toIso3(locale);
        URI deviceLink = smartIdClient.createDynamicContent()
                .withSchemeName(smartIdConfigurationProperties.getSchemaName())
                .withDeviceLinkBase(session.deviceLinkBase().toString())
                .withDeviceLinkType(DeviceLinkType.QR_CODE)
                .withSessionType(SessionType.AUTHENTICATION)
                .withSessionToken(session.sessionToken())
                .withElapsedSeconds(elapsedTime.getSeconds())
                .withLang(language)
                .withDigest(session.rpChallenge().toBase64EncodedValue())
                .withInteractions(session.interactions())
                .withRelyingPartyName(session.relyingPartyName())
                .buildDeviceLink(session.sessionSecret());
        return deviceLink.toString();
    }

    private Duration getElapsedTime(@NonNull SmartIdDeviceLinkSession session) {
        Duration result = Duration.between(session.startTime(), Instant.now(clock));
        if (result.isNegative()) {
            return Duration.ZERO;
        }
        return result;
    }

}
