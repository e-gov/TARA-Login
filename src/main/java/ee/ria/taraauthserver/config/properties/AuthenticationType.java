package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

@Getter
@AllArgsConstructor
public enum AuthenticationType {
    WEBAUTHN("webauthn", "webauthn", TaraScope.WEBAUTHN),
    ID_CARD("idcard", "id-card", TaraScope.IDCARD),
    MOBILE_ID("mID", "mobile-id", TaraScope.MID),
    SMART_ID("smartid", "smart-id", TaraScope.SMARTID),
    EIDAS("eidas", "eidas", TaraScope.EIDAS);

    private final String amrName;
    private final String propertyName;
    private final TaraScope scope;

    public static List<String> getFormalNames() {
        return stream(AuthenticationType.values())
                .map(a -> a.getScope().getFormalName())
                .collect(Collectors.toList());
    }
}
