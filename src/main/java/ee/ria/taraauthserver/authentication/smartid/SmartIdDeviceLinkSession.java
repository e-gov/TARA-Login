package ee.ria.taraauthserver.authentication.smartid;

import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import lombok.Builder;
import lombok.NonNull;

import java.net.URI;
import java.time.Instant;

@Builder

public record SmartIdDeviceLinkSession(
    @NonNull Instant startTime,
    @NonNull RpChallenge rpChallenge,
    @NonNull DeviceLinkAuthenticationSessionRequest request,
    @NonNull URI deviceLinkBase,
    @NonNull String sessionId,
    @NonNull String sessionToken,
    @NonNull String sessionSecret
) {

    public SmartIdDeviceLinkSession(
            @NonNull Instant startTime,
            @NonNull RpChallenge rpChallenge,
            @NonNull DeviceLinkAuthenticationSessionRequest request,
            @NonNull DeviceLinkSessionResponse response) {
        this(
                startTime,
                rpChallenge,
                request,
                response.deviceLinkBase(),
                response.sessionID(),
                response.sessionToken(),
                response.sessionSecret()
        );
    }

    public @NonNull String interactions() {
        return request.interactions();
    }

    public @NonNull String relyingPartyName() {
        return request.relyingPartyName();
    }

}
