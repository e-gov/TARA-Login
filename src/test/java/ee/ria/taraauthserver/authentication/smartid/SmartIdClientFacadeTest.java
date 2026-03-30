package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.authentication.common.AuthenticationDisplayTextFactory;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.utils.MockitoUtil;
import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.DeviceLinkAuthenticationSessionRequestBuilder;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.With;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static ee.ria.taraauthserver.utils.MockitoUtil.ANSWER_THROW_EXCEPTION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
class SmartIdClientFacadeTest {

    SmartIdClientFacade facade;

    SmartIdClient smartIdClient;
    RpChallengeService rpChallengeService;
    SmartIdConfigurationProperties configurationProperties;
    AuthenticationDisplayTextFactory smartIdDisplayTextFactory;
    DeviceLinkAuthenticationResponseValidator responseValidator;
    Clock clock;

    @BeforeEach
    void setUp() {
        smartIdClient = mock(SmartIdClient.class, ANSWER_THROW_EXCEPTION);
        rpChallengeService = mock(RpChallengeService.class, ANSWER_THROW_EXCEPTION);
        configurationProperties = new SmartIdConfigurationProperties();
        smartIdDisplayTextFactory = mock(AuthenticationDisplayTextFactory.class, ANSWER_THROW_EXCEPTION);
        responseValidator = mock(DeviceLinkAuthenticationResponseValidator.class, ANSWER_THROW_EXCEPTION);
        clock = Clock.fixed(Instant.parse("2026-03-23T12:00:00Z"), ZoneId.of("Europe/Tallinn"));
        facade = new SmartIdClientFacade(
                smartIdClient,
                rpChallengeService,
                configurationProperties,
                smartIdDisplayTextFactory,
                responseValidator,
                clock
        );
        configurationProperties.setRelyingPartyName("relying-party-name");
        configurationProperties.setRelyingPartyUuid("16c59910-6283-4e6f-ab5d-4cefca656df5");
    }

    @Nested
    class InitDeviceLinkSession {

        @Test
        void whenNoRelyingPartyProvided_defaultRelyingPartyUsed() throws URISyntaxException {
            String clientDisplayName = "An Information System";
            String sessionId = "a546643d-dabf-4cec-a087-2da2cc5c0565";
            String sessionToken = "<the-session-token>";
            String sessionSecret = "<the-session-secret>";
            URI deviceLinkBase = new URI("https://localhost:9999/device-link-base");
            String interactions = "<interactions>";
            Instant now = Instant.now(clock);
            RpChallenge rpChallenge = new RpChallenge("<rp-challenge>".getBytes(UTF_8));
            String displayText = "<display-text>";

            DeviceLinkSessionResponse sessionResponse = new DeviceLinkSessionResponse(
                    sessionId,
                    sessionToken,
                    sessionSecret,
                    deviceLinkBase
            );
            DeviceLinkAuthenticationSessionRequest sessionRequest = new DeviceLinkAuthenticationSessionRequest(
                    configurationProperties.getRelyingPartyUuid(),
                    configurationProperties.getRelyingPartyUuid(),
                    "<the-certificate-level>",
                    null,
                    null,
                    interactions,
                    null,
                    Set.of("<a-capability>"),
                    "<the-initial-callback-url>"
            );

            DeviceLinkAuthenticationSessionRequestBuilder sessionRequestBuilderMock = new MockRequestBuilderBuilder()
                    .withExpectedValues(MockSessionRequestValues.builder()
                            .rpChallenge(rpChallenge.toBase64EncodedValue())
                            .interactions(List.of(DeviceLinkInteraction.confirmationMessage(displayText)))
                            .certificateLevel(AuthenticationCertificateLevel.QUALIFIED)
                            .build())
                    .withInitAuthenticationSessionResult(sessionResponse)
                    .withGetAuthenticationSessionRequestResult(sessionRequest)
                    .build();
            doReturn(sessionRequestBuilderMock)
                    .when(smartIdClient).createDeviceLinkAuthentication();
            doReturn(displayText)
                    .when(smartIdDisplayTextFactory).createLoginDisplayText(clientDisplayName);
            doReturn(rpChallenge)
                    .when(rpChallengeService).getRpChallenge();

            SmartIdDeviceLinkSession result = facade.initDeviceLinkSession(clientDisplayName, null);

            assertThat(result).isEqualTo(new SmartIdDeviceLinkSession(
                    now,
                    rpChallenge,
                    sessionRequest,
                    sessionResponse
            ));
        }

    }

    @With
    @AllArgsConstructor
    @NoArgsConstructor
    static class MockRequestBuilderBuilder {

        MockSessionRequestValues expectedValues;
        Answer<DeviceLinkSessionResponse> initAuthenticationSessionAnswer;
        Answer<DeviceLinkAuthenticationSessionRequest> getAuthenticationSessionRequestAnswer;

        public MockRequestBuilderBuilder withInitAuthenticationSessionResult(DeviceLinkSessionResponse result) {
            return withInitAuthenticationSessionAnswer(invocation -> result);
        }

        public MockRequestBuilderBuilder withGetAuthenticationSessionRequestResult(
                DeviceLinkAuthenticationSessionRequest result) {
            return withGetAuthenticationSessionRequestAnswer(invocation -> result);
        }

        public DeviceLinkAuthenticationSessionRequestBuilder build() {
            Objects.requireNonNull(expectedValues);

            DeviceLinkAuthenticationSessionRequestBuilder result =
                    mock(DeviceLinkAuthenticationSessionRequestBuilder.class, MockitoUtil.ANSWER_THROW_EXCEPTION);
            lenient()
                    .doAnswer(Answers.RETURNS_SELF)
                    .when(result).withRpChallenge(any());
            lenient()
                    .doAnswer(Answers.RETURNS_SELF)
                    .when(result).withInteractions(any());
            lenient()
                    .doAnswer(Answers.RETURNS_SELF)
                    .when(result).withCertificateLevel(any());
            lenient()
                    .doAnswer(Answers.RETURNS_SELF)
                    .when(result).withRelyingPartyName(any());
            lenient()
                    .doAnswer(Answers.RETURNS_SELF)
                    .when(result).withRelyingPartyUUID(any());
            if (initAuthenticationSessionAnswer != null) {
                doAnswer(invocation -> {
                    verify(result).withRpChallenge(expectedValues.rpChallenge());
                    verify(result).withInteractions(expectedValues.interactions());
                    verify(result).withCertificateLevel(expectedValues.certificateLevel());
                    if (expectedValues.relyingPartyName() != null) {
                        verify(result).withRelyingPartyName(expectedValues.relyingPartyName());
                    }
                    if (expectedValues.relyingPartyUuid() != null) {
                        verify(result).withRelyingPartyUUID(expectedValues.relyingPartyUuid());
                    }
                    verifyNoMoreInteractions(result);
                    return initAuthenticationSessionAnswer.answer(invocation);
                }).when(result).initAuthenticationSession();
            }
            if (getAuthenticationSessionRequestAnswer != null) {
                doAnswer(invocation -> {
                    verify(result).initAuthenticationSession();
                    verifyNoMoreInteractions(result);
                    return getAuthenticationSessionRequestAnswer.answer(invocation);
                }).when(result).getAuthenticationSessionRequest();
            }

            return result;
        }

    }

    @Builder
    record MockSessionRequestValues(
            String rpChallenge,
            List<DeviceLinkInteraction> interactions,
            AuthenticationCertificateLevel certificateLevel,
            String relyingPartyName,
            String relyingPartyUuid
    ) {}


}
